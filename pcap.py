from dataclasses import dataclass
from struct import *

header_size = 4 + 2 + 2 + 4 + 4 + 4 + 4

@dataclass
class Pcap:
    magic_number: bytes
    version_major: int
    version_minor: int
    thiszone: bytes
    sigfigs: bytes
    snaplen: int
    network: int

    def __len__(self):
        return header_size

def parse(data):
    header = data[:header_size]
    payload = data[header_size:]
    m_n, v_ma, v_mi, tz, sig, sl, net = unpack('<LHHLLII', header)

    # return Pcap_header_structure and Pcap_payload
    return Pcap(m_n, v_ma, v_mi, tz, sig, sl, net), payload

def skip(data):
    return data[header_size:]