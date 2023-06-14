from dataclasses import dataclass
from struct import *

header_size = 1 + 1 + 2 + 2 + 2 + 1 + 1 + 2 + 4 + 4

@dataclass
class IP:
    version_and_header_size: bytes
    service: bytes
    packet_length: int
    identification: int
    flag_and_fragment_offset: bytes
    ttl: int
    protocol: int
    header_checksum: bytes
    src_ip: str
    dst_ip: str

    # return header length
    def __len__(self):
        return header_size
    
def parse(data):
    header = data[:header_size]
    payload = data[header_size:]
    VandHS, svc, pl, iden, FandFO, ttl, protocol, head_chk, s_ip, d_ip = unpack('<BBHHHBBH4s4s', header)

    return IP(VandHS, svc, pl, iden, FandFO, ttl, protocol, head_chk, s_ip, d_ip), payload