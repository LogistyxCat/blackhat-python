# Ver. 1.1
# Requires admin access on system
# Usage: python ./packetSniffer.py host_ip_address

import os, sys, time, socket, struct, threading
from ctypes import Structure, c_ubyte, c_ushort, c_ulong, sizeof


# IP packet headers
class IP(Structure):
    _fields_ = [
        ("ihl",          c_ubyte, 4),
        ("version",      c_ubyte, 4),
        ("tos",          c_ubyte),
        ("len",          c_ushort),
        ("id",           c_ushort),
        ("offset",       c_ushort),
        ("ttl",          c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum",          c_ushort),
        ("src",          c_ulong),
        ("dst",          c_ulong)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # Map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        # Human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

        # Human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class ICMP(Structure):

    _fields_ = [
        ("type",         c_ubyte),
        ("code",         c_ubyte),
        ("checksum",     c_ushort),
        ("unused",       c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer):
        pass


def help():
    print("BHP Packet Scanner / ICMP sniffer")
    print("Usage: python ./packetSniffer.py host_ip_address")
    print("Examples:")
    print("\tpython ./packetSniffer 192.128.0.101")
    print("\tpython ./packetSniffer 172.168.1.4")
    exit()


def main():
    # Host IP to listen on
    try:
        host = sys.argv[1]
    except:
        help()

    # Create a raw socket and bind it to the public interface
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP # Sniff everything
    else:
        socket_protocol = socket.IPPROTO_ICMP # Sniff only ICMP

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    except:
        print("[!] Insufficient permissions, exiting!")
        exit()

    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # If the host is Windows, send an IOCTL to set promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # Read in all the packets
    try:
        while True:
            # Read in a packet
            raw_buffer = sniffer.recvfrom(65565)[0]

            # Create an IP header from the first 20 bytes of the buffer
            ip_header = IP(raw_buffer[0:20])

            # Print out the protocol that was detected and the hosts
            print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

            # If ICMP
            if ip_header.protocol == "ICMP":
                # Calculate the offset
                offset = ip_header.ihl * 4

                buf = raw_buffer[offset:offset + sizeof(ICMP)]

                # Create our ICMP structure
                icmp_header = ICMP(buf)

                print("ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code))

    except KeyboardInterrupt:
        # Cleanup the promiscuous Windows mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

main()
