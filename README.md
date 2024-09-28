# Final-Project-Milestone-2
## Project Overview

This project is part of my final project for a 5G diploma offered by Siemens, where I am tasked with generating and streaming ORAN Ethernet packets with specific configurations. The project aims to simulate an ORAN data flow over an Ethernet network, adhering to the required specifications for packet alignment, header construction, and payload handling.

### Key Objectives

- Generate ORAN user-plane packets with appropriate headers and payloads.
- Encapsulate ORAN packets within eCPRI (Common Public Radio Interface) packets.
- Encapsulate eCPRI packets within Ethernet frames, ensuring correct addressing, alignment, and Interframe Gap (IFG) padding.
- Implement packet fragmentation when packet sizes exceed the allowed limits.
- Ensure fields within ORAN packets increment appropriately with each frame, subframe, slot, and symbol generated.
