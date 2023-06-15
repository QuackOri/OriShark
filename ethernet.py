from dataclasses import dataclass
from struct import *

header_size = 6 + 6 + 2

@dataclass
class Ethernet:
    dst_mac: str
    src_mac: str
    e_type: bytes

    # return header length
    def __len__(self):
        return header_size

def build_mac_address(mac_address):
    mac_address_list = []
    for octet in mac_address:
        mac_address_list.append(octet)
    return ':'.join([str(octet) for octet in mac_address_list])

def parse(data):
    header = data[:header_size]
    payload = data[header_size:]
    dst_mac, src_mac, e_type = unpack('>6s6sH', header)
    dst_mac = build_mac_address(dst_mac)
    src_mac = build_mac_address(src_mac)

    # return Ethernet_header_structure and E 
    return Ethernet(dst_mac, src_mac, e_type), payload