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
    header_length: int
    flags: list[str]
    window: int
    checksum: bytes
    urgent_pointer: int

    def __len__(self):
        return tcp_header_size

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

def analysis_tcp_flags(flags_string):
    flag_strings = ['Nonce', 'CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']
    result_list = []
    if flags_string[:3] == 0:
        result_list.append("Reserved")
    flags_string = flags_string[3:]

    for i, v in enumerate(flags_string):
        if v == '1':
            result_list.append(flag_strings[i])
    return result_list

def divide_headerL_and_flags(headerL_and_flags):
    binary = format(headerL_and_flags, 'b').zfill(16)
    header_length = binary[:4]
    flags = binary[4:]
    flags_list = analysis_tcp_flags(flags)
    return int(header_length, 2), flags_list

def tcp_parse(data):
    header = data[:tcp_header_size]
    payload = data[tcp_header_size:]
    src_port, dst_port, s_number, ack_number, HaF, window, checksum, urgent_pointer = unpack(">HHIIHHHH", header)
    header_length, flags = divide_headerL_and_flags(HaF)

    return TCP(src_port, dst_port, s_number, ack_number, header_length, flags, window, checksum, urgent_pointer), payload
