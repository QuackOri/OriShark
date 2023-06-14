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

def is_ipv4(eh:e.Ethernet):
    if eh.e_type == 8:
        return True
    else:
        return False

def which_protocol(ih:i.IP):
    if ih.protocol == 6:
        return "TCP"
    elif ih.protocol == 17:
        return "UDP"

def analysis_name(name_string):
    number = name_string[0]
    index = 1
    result_string = b''
    while number != 0:
        # print(number)
        result_string += name_string[index:index+number]
        index += number
        number = name_string[index]
        # print("index", index, "number", number)
        index += 1
    return result_string, index

def analysis_query(query_string):
    name, index = analysis_name(query_string)
    type, q_class = unpack('>HH', query_string[index:index+4])
    index += 4
    return d.Query(name, type, q_class), query_string[index:]

def find_query(query_string, count):
    query_list = []
    next_string = query_string
    for _ in range(count):
        query, next_string = analysis_query(next_string)
        query_list.append(query)
    return query_list, next_string

def analysis_answer(answer_string):
    index = 2 + 2 + 2 + 4 + 2 + 4
    now = answer_string[:index]
    next_string = answer_string[index:]
    name, answer_type, answer_class, ttl, data_length, address = unpack(">HHHIH4s", now)
    return d.Answer(name, answer_type, answer_class, ttl, data_length, address), next_string

def find_answer(answer_string, count):
    answer_list = []
    next_string = answer_string
    for _ in range(count):
        answer, next_string = analysis_answer(next_string)
        answer_list.append(answer)
    return answer_list, next_string

def analysis_auth(auth_string):
    index = 2 + 2 + 2 + 4 + 2
    now = auth_string[:index]
    name, auth_type, auth_class, ttl, data_length = unpack(">HHHIH", now)
    now = auth_string[index:index+data_length]
    name_server = unpack(">{}s".format(data_length), now)
    next_string = auth_string[index+data_length:]
    return d.AuthNameServer(name, auth_type, auth_class, ttl, data_length, name_server), next_string

def find_auth_nameserver(auth_string, count):
    auth_list = []
    next_string = auth_string
    for _ in range(count):
        auth, next_string = analysis_auth(next_string)
        auth_list.append(auth)
    return auth_list, next_string

def analysis_addit(addit_string):
    index = 2 + 2 + 2 + 4 + 2 + 4
    now = addit_string[:index]
    next_string = addit_string[index:]
    name, addit_type, addit_class, ttl, data_length, address = unpack(">HHHIHI", now)
    return d.AdditionalRecord(name, addit_type, addit_class, ttl, data_length, address), next_string

def find_additional_record(addit_string, count):
    addit_list = []
    next_string = addit_string
    for _ in range(count):
        addit, next_string = analysis_addit(next_string)
        addit_list.append(addit)
    return addit_list, next_string

def print_answer_ip(answers:list[d.Answer]):
    print("------------------")
    for answer in answers:
        address_bytes = answer.address
        print(".".join([str(byte) for byte in address_bytes]))
    print("------------------")