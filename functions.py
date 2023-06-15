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

def print_answer_ip(answers:list[d.Answer]):
    print("------------------")
    for answer in answers:
        address_bytes = answer.address
        print(".".join([str(byte) for byte in address_bytes]))
    print("------------------")