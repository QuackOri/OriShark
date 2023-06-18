import ethernet as e
import ip as i
import packet as pkt
import dns as d
from struct import *

def read_file(file_path:str):
    fd = open(file_path, "rb")
    data = fd.read()
    fd.close()
    return data

##### for DNS
def print_answer_ip(answers:list[d.Answer]):
    print("------------------")
    for answer in answers:
        address_bytes = answer.address
        print(".".join([str(byte) for byte in address_bytes]))
    print("------------------")

##### for ARP, IP
def build_ip_address(ip_address):
    ip_address_list = []
    for ip in ip_address:
        ip_address_list.append(ip)
    return '.'.join([str(ip) for ip in ip_address_list])

##### for Etehrnet, ARP
def build_mac_address(mac_address):
    mac_address_list = []
    for octet in mac_address:
        mac_address_list.append(octet)
    return ':'.join([str(octet) for octet in mac_address_list])