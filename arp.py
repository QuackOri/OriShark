from dataclasses import dataclass
from struct import *
import functions as f

header_size = 2 + 2 + 1 + 1 + 2 + 6 + 4 + 6 + 4

@dataclass
class ARP:
    hw: bytes
    protocol_type: bytes
    hardware_address_length: bytes
    protocol_address_length: bytes
    opcode: bytes
    source_hardware_address: str
    source_protocol_address: str
    target_hardware_address: str
    target_protocol_address: str

    # return header length
    def __len__(self):
        return header_size
    

def parse(data):
    header = data[:header_size]

    hw, protocol_type, mac_length, ip_length, opcode, s_mac, s_ip, t_mac, t_ip \
        = unpack('HHBBH6s4s6s4s', header)
    
    s_mac = f.build_mac_address(s_mac)
    s_ip = f.build_ip_address(s_ip)
    t_mac = f.build_mac_address(t_mac)
    t_ip = f.build_ip_address(t_ip)

    return ARP(hw, protocol_type, mac_length, ip_length, opcode, s_mac, s_ip, t_mac, t_ip)