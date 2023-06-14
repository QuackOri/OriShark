from dataclasses import dataclass
from struct import *

header_size = 2 + 2 + 2 + 2

@dataclass
class UDP:
    src_port: int
    dst_port: int
    length: int
    checksum: bytes


    # return header length
    def __len__(self):
        return header_size
    
def udp_parse(data):
    header = data[:header_size]
    payload = data[header_size:]
    # print(header)
    src_port, dst_port, length, checksum = unpack('>HHHH', header)

    return UDP(src_port, dst_port, length, checksum), payload