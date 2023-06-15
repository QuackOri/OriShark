from dataclasses import dataclass
from struct import *

header_size = 1 + 1 + 2 + 2 + 2 + 1 + 1 + 2 + 4 + 4

@dataclass
class IP:
    version: int
    header_length: int
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

def divide_version_and_headerL(v_and_headerL):
    binary = format(v_and_headerL, 'b').zfill(8)
    version = binary[:4]
    header_length = binary[4:]
    return int(version, 2), int(header_length, 2)

def build_ip_address(ip_address):
    ip_address_list = []
    for ip in ip_address:
        ip_address_list.append(ip)
    return '.'.join([str(ip) for ip in ip_address_list])

def parse(data):
    header = data[:header_size]
    payload = data[header_size:]
    VandHS, svc, pl, iden, FandFO, ttl, protocol, head_chk, s_ip, d_ip = unpack('>BBHHHBBH4s4s', header)
    version, header_length = divide_version_and_headerL(VandHS)
    s_ip = build_ip_address(s_ip)
    d_ip = build_ip_address(d_ip)

    return IP(version, header_length, svc, pl, iden, FandFO, ttl, protocol, head_chk, s_ip, d_ip), payload