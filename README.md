# BPFdoor Listener [IN DEVELOPMENT]
[!] This script listens for specially-crafted packets and executes embedded system commands.
[!] For Linux users. Requires root privileges to sniff packets using Scapy.

## Function:
- Listens for UDP packets on the specified interface
- If packet payload contains a "magic word" and base64-encoded command, it decodes and executes it
- Designed for educational purposes only

## Requirements:
pip install scapy

-----------------------------------------------------------------------------------------------------

# BPFdoor Sender [IN DEVELOPMENT]
[!] This script sends a crafted UDP packet containing a hidden base64-encoded shell command.
[!] Only works when the listener (BPFdoor.py) is running on the target system.

## Function:
- Takes a command from the user
- Encodes it in base64
- Sends it as a UDP packet with a magic identifier to the target

## Requirements:
pip install scapy
