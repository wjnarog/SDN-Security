#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP

# Version value for OpenFlow 1.3
OF_VERSION_13 = 0x04

# type value for OpenFlow packet_in message
PACKET_IN = 10

# OpenFlow header: 1 byte (verison) + 1 byte (type) + 2 bytes (length) + 4 bytes (xid) = 8 bytes
OF_HEADER_LEN = 8

# Threshold that traffic is considered DoS
DOS_THRESHOLD = 1000

# dict to store counts based on src IP + port
counts = {}
window_counts = {}

def handle_pkt(pkt):
    # check if packet has IP and TCP headers
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    
    # check if packet has a payload 
    payload = bytes(pkt[TCP].payload)
    if not payload:
        return

    #check if packet is a packet_in msg
    hits = count_packet_ins(payload)
    if hits == 0:
        return

    # store/update packet_in count value
    key = (pkt[IP].src, pkt[TCP].sport)
    counts[key] = counts.get(key,0) + hits
    # store packet_in count within a certain window for DoS protection
    window_counts[key] = window_counts.get(key,0) + hits
    
    # print out the live info, if necessary
    #print(f"Packet_In from {key[0]}:{key[1]}  -->  current count is {counts[key]}")

def count_packet_ins(payload):
    payload_len = len(payload)
    i = 0
    counter = 0

    # loop through the bytes of the payload after the header
    while i + OF_HEADER_LEN <= payload_len:
        version = payload[i]
        msg_type = payload[i+1]
        length = int.from_bytes(payload[i+2:i+4], "big") #big endianness
        if length < OF_HEADER_LEN:
            # if past the length of the payload, then break
            break
        if version == OF_VERSION_13 and msg_type == PACKET_IN:
            # if version is 1.3 and the msg is Packet_in, then increment
            counter += 1

        # move to the next message in the packet
        i += length

    return counter 

def print_counts(interval):
    # clear screen and move cursor to the front
    print("\033[2J\033[H", end="")
    print(f"PacketIn Monitor  (refresh every {interval}s)")
    print("-" * 50)
    print(f"{'SOURCE (switch IP:port)':<30}{'PACKET_IN COUNT':>20}")
    print("-" * 50)
    
    for (ip, port), count in sorted(counts.items(), key=lambda item: item[1],reverse=True):
        src = f"{ip}:{port}"
        print(f"{src:<30}{count:>20}")

    print("-" * 50)
    print(f"{'TOTAL':<30}{sum(counts.values()):>20}")

def attack_check(threshold):
    for (ip, port), count in window_counts.items():
        if count > threshold:
            print("\n" + "!" * 50)
            print(f"ALERT: possible Dos from {ip}:{port}")
            print(f"   {count} Packet_Ins this window (threshold {threshold})")
            print("!" * 50 + "\n")

def main():
    interval = 2
    
    print("Listening on TCP:6653 ...")
    while True:
        sniff(iface="lo", filter="tcp port 6653", prn=handle_pkt, store=False, timeout=interval)
        print_counts(interval)
        attack_check(DOS_THRESHOLD)
        window_counts.clear()

if __name__ == "__main__":
    main()