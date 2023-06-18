from dataclasses import dataclass
from struct import *

header_size = 1 + 1 + 2 + 4

@dataclass
class ICMP:
    type: bytes
    code: bytes
    checksum: bytes
    rest_of_header: bytes

control_messages = [
    ["Echo reply"],
    [],
    [],
    ["Destination network unreachable", "Destination host unreachable", 'Destination protocol unreachable', \
     'Destination port unreachable', 'Fragmentation required, and DF flag set', 'Source route failed', 'Destination network unknown', \
     'Destination host unknown', 'Source host isolated', 'Network administratively prohibited', 'Host administratively prohibited', \
     'Network unreachable for ToS', 'Host unreachable for ToS', '	Communication administratively prohibited', 'Host Precedence Violation', \
     'Precedence cutoff in effect'],
    [],
    ['Redirect Datagram for the Network', 'Redirect Datagram for the Host', '	Redirect Datagram for the ToS & network', 'Redirect Datagram for the ToS & host'],
    [],
    [],
    ['Echo request (used to ping)'],
    ['Router Advertisement'],
    ['Router discovery/selection/solicitation'],
    ['TTL expired in transit', 'Fragment reassembly time exceeded'],
    ['Pointer indicates the error', 'Missing a required option', 'Bad length'],
    ['Timestamp'],
    ['Timestamp reply'],
    [],
    [],
    [],
    [],
    [],[],[],[],[],[],[],[],[],[],[], # 19 ~ 29
    ['Information Request'],
    [],[],[],[],[],[],[],[],[],[],[], # 31 ~ 41
    ['Request Extended Echo'],
    ['No Error', 'Malformed Query', 'No Such Interface', 'No Such Table Entry', 'Multiple Interfaces Satisfy Query']
]

def parse(data):
    header = data[:header_size]
    payload = data[header_size:]

    type, code, checksum, rest_of_header = unpack("BBH4s", header)
    control_message = control_messages[type][code]
    return ICMP(type, code, checksum, rest_of_header), control_message