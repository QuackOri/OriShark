from dataclasses import dataclass
from struct import *

udp_header_size = 2 + 2 + 2 + 2
tcp_header_size = 2 + 2 + 4 + 4 + 2 + 2 + 2 + 2

@dataclass
class TCP:
    src_port: int
    dst_port: int
    sequence_number: int
    acknowledgment_number: int
    header_length_and_flags: bytes
    window: int
    checksum: bytes
    urgent_pointer: int

@dataclass
class UDP:
    src_port: int
    dst_port: int
    length: int
    checksum: bytes


    # return header length
    def __len__(self):
        return udp_header_size
    
def udp_parse(data):
    header = data[:udp_header_size]
    payload = data[udp_header_size:]
    # print(header)
    src_port, dst_port, length, checksum = unpack('>HHHH', header)

    return UDP(src_port, dst_port, length, checksum), payload

def tcp_parse(data):
    header = data[:tcp_header_size]
    payload = data[tcp_header_size:]
    src_port, dst_port, s_number, ack_number, HaF, window, checksum, urgent_pointer = unpack("HHIIHHHH", header)

    return TCP(src_port, dst_port, s_number, ack_number, HaF, window, checksum, urgent_pointer), payload