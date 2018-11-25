# Ver. 1.1
# Requires admin access on system
# Note: In Windows, the firewall may mess with ICMP packets, which can break the scanner
# Usage: python ./scanner.py host_ip_address host_subnet

import os, sys, time, socket, struct, threading
from ctypes import Structure, c_ubyte, c_ushort, c_ulong, sizeof
from netaddr import IPNetwork, IPAddress

# Magic string we are looking for
magic_string = "PYTHON4LIFE!"


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


# Spray UDP datagrams
def udp_sender(subnet, magic_string):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_string,("%s" % ip,65212))
        except:
            pass


def help():
    print("BHP Subnet scanner")
    print("Identifies online hosts using UDP and ICMP packets.")
    print("Note: While this does work on Windows, the firewall may not like this.")
    print("Usage: python ./packetSniffer.py host_ip_address target_subnet")
    print("Examples:")
    print("\tpython ./scanner.py 192.128.0.101 192.168.0.0/24")
    print("\tpython ./scanner.py 172.168.1.4 172.16.0.0/16")
    print("\tpython ./scanner.py 10.10.100.5 10.0.0.0/8")
    exit()


def main():
    # Host to listen on and subnet to spray
    try:
        host = sys.argv[1]
        subnet = sys.argv[2]
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

    # Start sending magic packets
    t = threading.Thread(target=udp_sender, args=(subnet,magic_string))
    t.start()

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

                # Now check to TYPE and CODE 3
                if icmp_header.code == 3 and icmp_header.type == 3:
                    # Make sure host is in the target subnet
                    if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                        # Check if magic_string is present
                        if raw_buffer[len(raw_buffer)-len(magic_string):] == magic_string:
                            print("Host Up: %s" % ip_header.src_address)

    except KeyboardInterrupt:
        # Cleanup the promiscuous Windows mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

main()
