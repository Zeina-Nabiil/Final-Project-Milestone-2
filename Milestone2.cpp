#include <iostream>
#include <cstdint>
#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <cmath>
#include <utility> // for std::pair

using namespace std;

// Declare Global variables to store the values in the setup file
    // Ethernet parameters:
    int LineRate , CaptureSizeMs , MinNumOfIFGsPerPacket, MaxPacketSize , BurstSize, BurstPeriodicity;
    std::string Dest_Address , Source_Address;

    // ECPRI parameters:
    uint8_t eCPRI_Seqid = 0 ; // ranges from 0 to 255

    //ORAN parameters:
    int oran_scs ;
    double oran_Maxprb , oran_nrbPerPacket;
    const int MAX_ALLOWED_ORANPACKET_SIZE = 1466;

    std::string oran_payloadType ,oran_payload;

    // Structure to hold IQ data
    std::vector<std::pair<int, int> > iqData;

    // variables for calculations
    int slots , No_of_Frames , No_of_Subframes , No_of_Slots , No_of_Symb , PacketsPerSymbol , No_of_packets , No_of_bits ,No_of_ifgs ;
    int Frame_duration = 10 ; // 10 ms

// Function to read the setup file
bool readSetupFile(const std::string& setupFilePath)
{
    std::ifstream SetupFile(setupFilePath);
    if (!SetupFile)
     {
        std::cerr << "Error opening the Setup File." << std::endl;
        return false;
     }

    std::string line;
    while (std::getline(SetupFile, line))
    {
        std::istringstream obj(line);
        std::string key, value;
        if (std::getline(obj, key, '=') && std::getline(obj, value))
        {
            try {
                if (key == "Eth.LineRate")
                    LineRate = std::stoi(value);
                else if (key == "Eth.CaptureSizeMs")
                    CaptureSizeMs = std::stoi(value);
                else if (key == "Eth.MinNumOfIFGsPerPacket")
                    MinNumOfIFGsPerPacket = std::stoi(value);
                else if (key == "Eth.DestAddress")
                    Dest_Address = value;
                else if (key == "Eth.SourceAddress")
                    Source_Address = value;
                else if (key == "Eth.MaxPacketSize")
                    MaxPacketSize = std::stoi(value);
                else if (key == "Eth.BurstSize")
                    BurstSize = std::stoi(value);
                else if (key == "ECPRI.SeqId")
                    eCPRI_Seqid = std::stoi(value);
                else if (key == "ORAN.SCS")
                    oran_scs = std::stoi(value);
                else if (key == "ORAN.MaxNRB")
                    oran_Maxprb = std::stoi(value);
                else if (key == "ORAN.NRBperpacket")
                    oran_nrbPerPacket = std::stoi(value);
                else if (key == "ORAN.PayloadType")
                    oran_payloadType = value;
                else if (key == "ORAN.Payload")
                    oran_payload = value;
                }
             catch (const std::invalid_argument& e)
              {
                std::cerr << "Invalid value for " << key << ": " << value << std::endl;
                return false;
              }
             catch (const std::out_of_range& e)
              {
                std::cerr << "Value out of range for " << key << ": " << value << std::endl;
                return false;
              }
       }
    }
    SetupFile.close();
    return true;
}


// Function to read exactly 552 I/Q pairs (2208 bytes) for the ORAN payload, looping over the file if necessary
std::vector<uint8_t> generateOranPayloadWithLooping(const std::string &filename)
{
    std::vector<uint8_t> payload;
    const size_t required_pairs = 552;
    size_t pairs_read = 0;

    while (pairs_read < required_pairs) {
        std::ifstream iqFile(filename);
        if (!iqFile.is_open()) {
            std::cerr << "Error: Unable to open the IQ file." << std::endl;
            return {};
        }

        int32_t i_value, q_value;
        // Read I/Q values until we reach the end of the file or gather the required pairs
        while (pairs_read < required_pairs && (iqFile >> i_value >> q_value)) {
            // Convert to 16-bit signed integers
            int16_t i_converted = static_cast<int16_t>(i_value);
            int16_t q_converted = static_cast<int16_t>(q_value);

            // Append I and Q in little-endian format
            payload.push_back(static_cast<uint8_t>(i_converted & 0xFF));
            payload.push_back(static_cast<uint8_t>((i_converted >> 8) & 0xFF));
            payload.push_back(static_cast<uint8_t>(q_converted & 0xFF));
            payload.push_back(static_cast<uint8_t>((q_converted >> 8) & 0xFF));

            pairs_read++;
        }
        iqFile.close();

        // If we reached the end of the file without gathering enough pairs, restart the loop to read from the beginning again
        if (pairs_read < required_pairs) {
            std::cout << "Reached end of IQ file. Restarting to gather more samples..." << std::endl;
        }
    }

    return payload;
}


// Helper function to convert string MAC address to uint64_t
uint64_t macAddressToUInt64(const std::string& mac)
{
    uint64_t macAddress = 0;
    std::istringstream iss(mac);
    std::string byteStr;
    while (std::getline(iss, byteStr, ':')) {
        macAddress = (macAddress << 8) + std::stoul(byteStr, nullptr, 16);
    }
    return macAddress;
}

class EthernetPacket {
public:
    static const uint64_t PreambleAndSFD = 0xFB555555555555D5; // 8 bytes (64 bits)
    uint64_t DestAddress;  // 6 bytes (48 bits)
    uint64_t SourceAddress; // 6 bytes (48 bits)
    static const uint16_t EtherType = 0xAEFE;  // 2 bytes (16 bits), eCPRI Protocol
    std::vector<uint8_t> Payload;  // varies from 46 to 1474 bytes
    uint32_t FCS;  // 4 bytes (32 bits)
    const int MaxPayloadSize = 1474;
    const int MinPayloadSize = 46;

    // Generate the payload with the size ensuring it's within valid bounds
    void GeneratePayload(size_t PayloadSize)
    {
        if (PayloadSize < MinPayloadSize)
        {
            PayloadSize = MinPayloadSize; // Payload = 46 bytes
        }
        else if (PayloadSize > MaxPayloadSize)
        {
            PayloadSize = MaxPayloadSize; // Payload = 1474 bytes
        }

    }

    // Compute CRC32 for the given frame (without FCS)
    uint32_t ComputeCRC32(const std::vector<uint8_t>& frame) {
        uint32_t crc = 0xFFFFFFFF;
        for (uint8_t byte : frame) {
            crc ^= (uint32_t)byte;
            for (int i = 0; i < 8; ++i) {
                if (crc & 1)
                    crc = (crc >> 1) ^ 0x04C11DB7;
                else
                    crc >>= 1;
            }
        }
        return ~crc;  // Finalize the CRC by inverting all bits
    }

   // Function to generate the full Ethernet packets
    std::vector<uint8_t> GenerateEthernetPackets(const std::vector<uint8_t>& etherpayload) // pass the ecpri packet as an argument
    {
          std::vector<uint8_t> Packet;

          // 1. Add Preamble and SFD (8 bytes)
          uint64_t preambleandSFD = PreambleAndSFD;
          for (int i = 7; i >= 0; --i)
            {
              Packet.push_back((preambleandSFD >> (i * 8)) & 0xFF); //shift right by i bytes
            }

          // 2. Add Destination MAC Address (6 bytes)
          for (int i = 5; i >= 0; --i)
            {
              Packet.push_back((DestAddress >> (i * 8)) & 0xFF);
            }

          // 3. Add Source MAC Address (6 bytes)
          for (int i = 5; i >= 0; --i)
            {
              Packet.push_back((SourceAddress >> (i * 8)) & 0xFF);
            }

          // 4. Add EtherType (2 bytes)
          uint16_t etherType = EtherType;
          for (int i = 1; i >= 0; --i)
            {
              Packet.push_back((etherType >> (i * 8)) & 0xFF);
            }

          // 5. Add Payload
          // check on payload if it needs fragmentation
          Packet.insert(Packet.end(),etherpayload.begin(),etherpayload.end());

          // 6. Compute FCS (without including the FCS itself in the frame)
          FCS = ComputeCRC32(Packet);

          // 7. Add FCS (4 bytes)
          for (int i = 3; i >= 0; --i)
            {
              Packet.push_back((FCS >> (i * 8)) & 0xFF);
            }

    return Packet;
   }

    // Add Inter-Frame Gap (IFG)
    void AddIFG(std::vector<uint8_t>& Packet)
    {
        const uint8_t IFG = 0x07 ;
        while (Packet.size() % 4 != 0)
         {
            Packet.push_back(IFG);  // Add one-byte IFG (0x07) to make it 4-byte aligned
         }
    }
};

class eCPRI_Packet : public EthernetPacket
{
    public:
    const uint8_t eCPRI_Version = 0x00 ; // first byte is zero dummies
    const uint8_t eCPRI_Message = 0x00 ; // user plane (indicates the type of service conveyed by the message type)
    size_t eCPRI_Payload ; // indicates the size in bytes of the payload part , Max supported payload = 65535 bits = 8191.875 bytes
    const double MaxSupprotedPayload = 8191.875;
    const uint8_t eCPRI_PC_RTC = 0x00 ;  // fixed

    // default constructor
    eCPRI_Packet ()
    {

    }

    // function to generate ECPRI packet
    std::vector<uint8_t> GenerateECPRIPacket (const std::vector<uint8_t>& oranPacket) // takes oran packet as an argument to be its payload
    {
        std::vector<uint8_t> eCPRIPacket;

        // 1. Add first byte
           eCPRIPacket.push_back(eCPRI_Version);

        // 2. Add ecpriMessage
           eCPRIPacket.push_back(eCPRI_Message);

        // 3. Add ecpriPayload
            size_t eCPRI_Payload = oranPacket.size();
            if (eCPRI_Payload > MaxSupprotedPayload)
            {
                cerr << "Packet size is not valid , increase maxPacketSize or decrease the NRBs used." << endl;
            }
            else
            {
                eCPRIPacket.push_back(static_cast<uint8_t>(eCPRI_Payload >> 8));  // Higher byte of the size
                eCPRIPacket.push_back(static_cast<uint8_t>(eCPRI_Payload & 0xFF)); // Lower byte of the size
            }

        // 4. Add ecpriPC/RTC
           eCPRIPacket.push_back(eCPRI_PC_RTC);

        // 5. Add ecpriSeqid
           eCPRIPacket.push_back(eCPRI_Seqid);

        // 6. Add ORAN packet as ecpri payload
           eCPRIPacket.insert(eCPRIPacket.end(), oranPacket.begin(), oranPacket.end());

       return eCPRIPacket;
    }


};

class ORAN_Packet : public eCPRI_Packet
{
    public:
    const uint8_t ORAN_FirstByte = 0x00 ;  // includes dataDirection , payloadVersion and filterIndex
    const uint16_t SectionID = 0x000 ;
    unsigned rb : 1 ; // 1 bit field for rb
    unsigned symInc : 1 ;  // 1 bit field for symInc
    uint8_t FrameID , SubframeID , SlotID , SymbolID ;
    uint8_t numPrbu = oran_nrbPerPacket; // numPrbu field : number of contiguous PRBs per data section
    uint16_t startPrbu; //used to indicate the starting Physical Resource Block (PRB) unit within a specific data section
    std::vector<uint8_t> oranPayload;
    // Constructor to initialize fields
    ORAN_Packet()
        : rb(0), symInc(0), FrameID(0), SubframeID(0), SlotID(0), SymbolID(0), startPrbu(0)
    {}

    // function to generate full ORAN packet
    std::vector<uint8_t> GenerateORANPacket(const std::vector<uint8_t>& payload, uint16_t startPrbu)
    {
       std::vector<uint8_t> ORANPacket;

          // 1. Add the first byte (dataDirection, payloadVersion, and filterIndex combined)
             ORANPacket.push_back(ORAN_FirstByte);

          // 2. Add FrameId
             ORANPacket.push_back(FrameID);

          // 3. Combine SubframeID (4 bits) with the first 4 bits of SlotID to make 1 byte
             uint8_t combinedHeader1 = (SubframeID << 4) | ((SlotID >> 2) & 0x0F);
             ORANPacket.push_back(combinedHeader1);

          // 4. Combine the remaining 2 bits of SlotID with SymbolID (6 bits) to make 1 byte
             uint8_t combinedHeader2 = ((SlotID & 0x03) << 6) | (SymbolID & 0x3F);
             ORANPacket.push_back(combinedHeader2);

          // 5. Add first 8 bits of the SectionID
             ORANPacket.push_back(static_cast<uint8_t>((SectionID >> 4) & 0xFF));

          // 6. Combine the remaining 4 bits of SectionID with rb, symInc, and the first 2 bits of startPrbu
             uint8_t combinedField = ((SectionID & 0x0F) << 4) | ((rb << 3) | (symInc << 2) | ((startPrbu >> 8) & 0x03));
             ORANPacket.push_back(combinedField);

          // 7. Add the remaining 8 bits of startPrbu
             ORANPacket.push_back(static_cast<uint8_t>(startPrbu & 0xFF));

          // 8. Add numPrbu (1 byte)
             ORANPacket.push_back(numPrbu);

          // 9. Add Payload
             oranPayload = payload;
             ORANPacket.insert(ORANPacket.end(), oranPayload.begin(), oranPayload.end());

      return ORANPacket;
   }

};

std::vector<ORAN_Packet> fragmentORANPacket(const std::vector<uint8_t>& ecpriPayload, int totalSize)
{
    std::vector<ORAN_Packet> fragments;
    // Calculate the number of fragments required
    int numFragments = (totalSize + MAX_ALLOWED_ORANPACKET_SIZE - 1) / MAX_ALLOWED_ORANPACKET_SIZE;

    for (int i = 0; i < numFragments; ++i) {
        int fragmentSize = std::min(MAX_ALLOWED_ORANPACKET_SIZE, totalSize - i * MAX_ALLOWED_ORANPACKET_SIZE);

        ORAN_Packet packet;
        packet.oranPayload.insert(packet.oranPayload.begin(), ecpriPayload.begin() + i * MAX_ALLOWED_ORANPACKET_SIZE,
                              ecpriPayload.begin() + i * MAX_ALLOWED_ORANPACKET_SIZE + fragmentSize);

        fragments.push_back(packet);
    }

    return fragments;
}

// function to increment ECPRI.Seqid
void increment_ECPRISeqid()
{
   eCPRI_Seqid++;
   if(eCPRI_Seqid >255)
   {
       eCPRI_Seqid = 0 ;
   }

}

void Calculations()
{
    // Calculations for frames , subframes , ... etc calculations
        int Mu;
        switch (oran_scs)
         {
           case 15:
            Mu = 0;
            break;
           case 30:
            Mu = 1;
            break;
           case 60:
            Mu = 2;
            break;
           default:
            std::cerr << "Invalid ORAN SCS value: " << oran_scs << std::endl;
         }

        slots = pow(2,Mu);
        cout<<"Number of slots per subframe are "<<slots<<endl;

        // step (1): Calculate the total number of frames
        No_of_Frames = CaptureSizeMs / Frame_duration ;
        cout<<"Number of Frames are "<<No_of_Frames<<endl;

        // step (2): Calculate the total number of subframes
        No_of_Subframes = No_of_Frames * 10 ; // 1 frame >> 10 subframe
        cout<<"Number of Subframes are "<<No_of_Subframes<<endl;

        // step (3): Calculate the total number of slots
        No_of_Slots = No_of_Subframes * slots ;
        cout<<"Number of total slots are "<<No_of_Slots<<endl;

        // step (4): Calculate the total number of symbols
        No_of_Symb = No_of_Slots * 14 ; // Assuming Normal CP
        cout<<"Number of total Symbols are "<<No_of_Symb<<endl;

        // step (5): Calculate the number of packets per symbol
        PacketsPerSymbol =  ceil(oran_Maxprb / oran_nrbPerPacket) ;
        cout<<"Number of Packets per Symbol are "<<PacketsPerSymbol<<endl;

        // step (6): Calculate the total number of ORAN packets
        No_of_packets  = PacketsPerSymbol * No_of_Symb;
        cout<<"Number of total ORAN Packets are "<<No_of_packets<<endl;

        // step (7): Calculate the number of bits per packet
        No_of_bits = oran_nrbPerPacket *12 * 2* 16;  // 1 RB >> 12 IQ sample assuming IQ bitwidth = 16 (16 for i and 16 for q)
        cout<<"Number of bits per ORAN packet are "<<No_of_bits<<endl;

        double No_of_bytes =  No_of_bits / 8 ;

        // step (8): Calculate the time of one packet
        double T_packet = ((MaxPacketSize + (MinNumOfIFGsPerPacket*1)) * 8) / (LineRate * pow(10.0,9.0)) ;

        // step (9): Calculate the total time taken by all packets in one frame
        double TotalTime = T_packet * (No_of_packets /2);

        // step (10): Calculate if there is time left in frame after transmission is done to send IFGs
        double Remaining_time = (Frame_duration / pow(10,3)) - TotalTime;
        cout<<"Remaining time is "<<Remaining_time<<endl;

        // step (11):
        No_of_ifgs = Remaining_time / (((MinNumOfIFGsPerPacket*1) * 8) / (LineRate * pow(10.0,9.0)));
        cout<<"Number of IFGs generated in the remaining time of the frame is "<<No_of_ifgs<<endl;
}

int main()
{
    //  Load setup file and iq file
    std::string setupFilePath = "/Users/zeina/Desktop/Project/SetupFile.txt";
    if (!readSetupFile(setupFilePath))
    {
        return 1;
    }

    std::string iqFilePath = "/Users/zeina/Desktop/Project/iq_file.txt";

    std::cout << "Setup file parameters loaded successfully." << std::endl;

    // Calculations for frames , subframes , ... etc calculations
    Calculations();

    std::vector<uint8_t> oranPayload = generateOranPayloadWithLooping(iqFilePath);
    if (oranPayload.empty())
    {
        std::cerr << "Error generating ORAN payload." << std::endl;
        return 1;
    }

    std::vector<uint8_t> ethernetPacketData;

    // Output to file
    std::ofstream OutputFile;
    OutputFile.open("/Users/zeina/Desktop/Project/OutputPackets.txt");

    if (!OutputFile)
    {
        std::cerr << "Error opening output file." << std::endl;
        return 1;
    }

    int byteCounter = 0;
    uint16_t currentPrbu = 0;  // Initialize the starting PRB index

// Loop through frames, subframes, slots, and symbols
for (int frameId = 0; frameId < No_of_Frames; ++frameId)
{
    OutputFile <<"Frame : "<<frameId<<endl;
    for (int subframeId = 0; subframeId < 10; ++subframeId)
    {
       for (int slotId = 0; slotId < slots; ++slotId)
       {
          for (int symbolId = 0; symbolId < 14; ++symbolId)
          {
              // since one ethernet packet carries one ecrpi instance whcih in return contains one oran instance
             // Therefore numbr of generated ethernet packets = number of generated ecpri packets = number of generated oran packets
               for(int packetIndex = 0; packetIndex < PacketsPerSymbol ; ++packetIndex)
                {
                  std::cout << "Generating ORAN packet " << (packetIndex + 1) << "/" << PacketsPerSymbol << std::endl;

                  // Generate ORAN packet
                   ORAN_Packet oranPacket;
                   oranPacket.FrameID= frameId;
                   oranPacket.SubframeID = subframeId;
                   oranPacket.SlotID = slotId;
                   oranPacket.SymbolID = symbolId;

                  // Calculate startPrbu based on current packet index and PRB allocation
                   oranPacket.startPrbu = currentPrbu;
                   currentPrbu += oran_nrbPerPacket;

                   std::vector<uint8_t> oranPacketData = oranPacket.GenerateORANPacket(oranPayload,oranPacket.startPrbu);

                  // check ths size of oran packets that it doesn't exceed 1466 if it does then it need fragmentation
                   if (oranPacketData.size() > MAX_ALLOWED_ORANPACKET_SIZE)
                    {
                      cerr << "ORAN packet size exceeds the maximum allowed. Fragmenting ....." <<endl;
                      auto fragmentedPackets = fragmentORANPacket(oranPacketData , oranPacketData.size());

                      cout << "Number of fragments created: " << fragmentedPackets.size() << endl;


                   for (auto &fragment : fragmentedPackets)
                    {
                      // Encapsulate the ORAN fragment in an eCPRI packet
                      eCPRI_Packet ecpriPacket;
                      std::vector<uint8_t> ecpriPacketData = ecpriPacket.GenerateECPRIPacket(fragment.oranPayload);

                      // Encapsulate the eCPRI packet in an Ethernet packet
                      EthernetPacket ethPacket;
                      ethPacket.DestAddress = macAddressToUInt64(Dest_Address);
                      ethPacket.SourceAddress = macAddressToUInt64(Source_Address);
                      ethernetPacketData = ethPacket.GenerateEthernetPackets(ecpriPacketData);

                      // Add IFG to align to 4 bytes
                      ethPacket.AddIFG(ethernetPacketData);

                      std::cout << "Generated Ethernet packet size: " << ethernetPacketData.size() << " bytes" << std::endl;

                      // increment ECPRI.Seqid for the next packet
                      increment_ECPRISeqid();

                      // Write to output file
                      for (uint8_t byte : ethernetPacketData)
                       {
                         OutputFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
                         byteCounter++;

                        if (byteCounter % 4 == 0)
                        {
                          OutputFile << "\n";
                        }
                       }
                     }
                    }
                   else
                {
                  // In case no need for fragmentation
                 // Encapsulate the ORAN fragment in an eCPRI packet
                 eCPRI_Packet ecpriPacket;
                 std::vector<uint8_t> ecpriPacketData = ecpriPacket.GenerateECPRIPacket(oranPacketData);

                // Encapsulate the eCPRI packet in an Ethernet packet
                EthernetPacket ethPacket;
                ethPacket.DestAddress = macAddressToUInt64(Dest_Address);
                ethPacket.SourceAddress = macAddressToUInt64(Source_Address);
                ethernetPacketData = ethPacket.GenerateEthernetPackets(ecpriPacketData);

                // Add IFG to align to 4 bytes
                ethPacket.AddIFG(ethernetPacketData);

                cout << "Generated Ethernet packet size: " << ethernetPacketData.size() << " bytes" << endl;

                // increment ECPRI.Seqid for the next packet
                increment_ECPRISeqid();

                // Write to the output file
                 for (uint8_t byte : ethernetPacketData)
                 {
                   OutputFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
                   byteCounter++;

                   if (byteCounter % 4 == 0)
                    {
                     OutputFile << "\n";
                    }
                 }

                }

     OutputFile << endl;


          }
       }
    }
  }

          // Add IFGs to be sent in the remaining time of the frame
          OutputFile <<"\nSending IFGs in the remaining time...."<<endl;
          for(int k = 0 ; k < No_of_ifgs ; k++)
          {
            OutputFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(0x07) << " ";
            if ((k + 1) % 4 == 0)
             {
                OutputFile << "\n";
             }
          }

           OutputFile << endl;


}
    OutputFile.close();

    return 0;
}
