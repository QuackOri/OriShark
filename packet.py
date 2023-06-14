from dataclasses import dataclass
from struct import *

header_size = 4 + 4 + 4 + 4

@dataclass
class Pcap:
    ts_sec: bytes
    ts_usec: bytes
    incl_len: bytes
    orig_len: bytes

    def __len__(self):
        return header_size

def parse(data):
    header = data[:header_size]
    payload = data[header_size:]
    ts_sec, ts_usec, incl_l, orig_l = unpack("<LLLL", header)

    return Pcap(ts_sec, ts_usec, incl_l, orig_l), payload

def skip(data):
    return data[header_size:]