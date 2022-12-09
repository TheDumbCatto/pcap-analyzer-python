import pyshark


# The class storing the unique packets found
class UniquePacket:
    def __init__ (self, ip_nguon, port_nguon, ip_dich, port_dich, giao_thuc, so_luong):
        self.ip_nguon = ip_nguon
        self.port_nguon = port_nguon
        self.ip_dich = ip_dich
        self.port_dich = port_dich
        self.giao_thuc = giao_thuc
        self.so_luong = so_luong
    
    def __str__(self):
        return "ip_nguon: {}, port_nguon: {}, ip_dich: {}, port_dich: {}, giao_thuc: {}, so_luong: {}".format(self.ip_nguon, self.port_nguon, self.ip_dich, self.port_dich, self.giao_thuc, self.so_luong)
        

# Function that checks whether a packet is unique in the packet list
# If the same packet is found, return the index of that packet in the packet list
# If no same packet is found, return -1
def find_unique_packet(pkt_list, src_ip, src_port, dst_ip, dst_port, protocol):
    for i, pkt in enumerate(pkt_list):
        if (pkt.ip_nguon == src_ip and pkt.port_nguon == src_port and pkt.ip_dich == dst_ip and pkt.port_dich == dst_port and pkt.giao_thuc == protocol):
            return i

    return -1


# Main function to analyze given pcap file
def parsepcap(pcap_file, pkt_filter=''):

    # Read the packets
    # Currently ignoring ARP packets and IPv6
    packets = pyshark.FileCapture(pcap_file, display_filter='eth.type != arp && not ipv6' + pkt_filter)

    # List of unique packets
    unique_packets = []

    # Iterate through read packets and start counting
    for packet in list(packets):

        # Extract all information for a unique packet
        src_ip = ''
        src_port = 0
        dst_ip = ''
        dst_port = 0
        protocol = ''
        # Extract address information
        if packet.ip.proto.showname_value.startswith('TCP'):
            src_ip = str(packet.ip.src)
            src_port = int(packet.tcp.srcport)
            dst_ip = str(packet.ip.dst)
            dst_port = int(packet.tcp.dstport)
        elif packet.ip.proto.showname_value.startswith('UDP'):
            src_ip = str(packet.ip.src)
            src_port = int(packet.udp.srcport)
            dst_ip = str(packet.ip.dst)
            dst_port = int(packet.udp.dstport)
        # Extract the protocols used
        protocols = [layer.layer_name for layer in packet.layers]
        protocol = protocols[len(protocols) - 1]

        # Check if the current packet is unique
        # If it is, increment the count by 1
        # If not then create a new UniquePacket and append to the list of unique packets
        if len(unique_packets) == 0: # First packet in the pcap file
            new_unique_packet = UniquePacket(src_ip, src_port, dst_ip, dst_port, protocol, 1)
            unique_packets.append(new_unique_packet)
        else:
            unique_packet_index = find_unique_packet(unique_packets, src_ip, src_port, dst_ip, dst_port, protocol)
            if unique_packet_index == -1:
                new_unique_packet = UniquePacket(src_ip, src_port, dst_ip, dst_port, protocol, 1)
                unique_packets.append(new_unique_packet)
            else:
                unique_packets[unique_packet_index].so_luong += 1
    return unique_packets

