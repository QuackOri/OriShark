from dataclasses import dataclass
from struct import *

udp_header_size = 2 + 2 + 2 + 2
tcp_header_size = 2 + 2 + 4 + 4 + 2 + 2 + 2 + 2

@dataclass
class TCP:
    src_port: int
    dst_port: int
    sequence_number: bytes
    acknowledgment_number: bytes
    header_length: int
    flags: str
    checksum: int
    urgent_pointer: int
    tcp_payload: bytes

    # return header length
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

def flags_parser(flags_bit: str) -> str:
    flags = ""
    if flags_bit[0] == "1":
        flags += "u"
    if flags_bit[1] == "1":
        flags += "a"
    if flags_bit[2] == "1":
        flags += "p"
    if flags_bit[3] == "1":
        flags += "r"
    if flags_bit[4] == "1":
        flags += "s"
    if flags_bit[5] == "1":
        flags += "f"
    return flags

def tcp_parse(data):
    src_port = unpack(">H", data[:2])[0]
    dst_port = unpack(">H", data[2:4])[0]
    seq_number = data[4:8]
    ack_number = data[8:12]
    header = protocol = unpack("<B", data[12:13])[0]
    header_length = int(header / 4)
    flags = unpack("<H", data[13:15])[0]
    flags_bit = format(flags, 'b')[-6:]
    flags = flags_parser(flags_bit)
    checksum = unpack("<H", data[15:17])[0]
    
    try:
        urgent_pointer = unpack("<H", data[17:19])[0]
    except:
        urgent_pointer = 0
    
    tcp_payload = data[tcp_header_size:]
    
    return TCP(src_port, dst_port, seq_number, ack_number, header_length, flags, checksum, urgent_pointer, tcp_payload), tcp_payload
