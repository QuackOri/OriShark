from dataclasses import dataclass
from struct import *

header_size = 2 + 2 + 2 + 2 + 2 + 2
global additional_size
global remain_size

@dataclass
class Query:
    name: str
    type: int
    query_class: int

@dataclass
class Answer:
    name: bytes
    answer_type: int
    answer_class: int
    ttl: int
    data_length: int
    address: bytes

@dataclass
class AuthNameServer:
    name: bytes
    auth_type: int
    auth_class: int
    ttl: int
    data_length: int
    name_server: str

@dataclass
class AdditionalRecord:
    name: bytes
    additional_type: int
    additional_class: int
    ttl: int
    data_length: int
    address: bytes

@dataclass
class DNSResponse:
    transaction_id: bytes
    flags: bytes
    questions: int
    answer_RRs: int
    authority_RRs: int
    additional_RRs: int
    queries: list[Query]
    answers: list[Answer]
    authoritative_nameservers: list[AuthNameServer]
    additional_records: list[AdditionalRecord]

    # return header length
    def __len__(self):
        if additional_size != 0 and remain_size != 0:
            return header_size + additional_size - remain_size
        else:
            return -1
    
def first_parse(data):
    global additional_size
    header = data[:header_size]
    payload = data[header_size:]
    t_id, flags, questions, ans, auth, addit = unpack('>HHHHHH', header)

    additional_size = len(payload)
    return DNSResponse(t_id, flags, questions, ans, auth, addit, [], [], [], []), payload

##########  Query  ##########
def analysis_name(name_string):
    number = name_string[0]
    index = 1
    result_list = []
    while number != 0:
        # print(number)
        result_list.append(name_string[index:index+number])
        index += number
        number = name_string[index]
        # print("index", index, "number", number)
        index += 1
    return b'.'.join([word for word in result_list]), index

def analysis_query(query_string):
    name, index = analysis_name(query_string)
    type, q_class = unpack('>HH', query_string[index:index+4])
    index += 4
    return Query(name, type, q_class), query_string[index:]

def find_query(query_string, count):
    query_list = []
    next_string = query_string
    for _ in range(count):
        query, next_string = analysis_query(next_string)
        query_list.append(query)
    return query_list, next_string

##########  Answer  ##########
def analysis_answer(answer_string):
    index = 2 + 2 + 2 + 4 + 2 + 4
    now = answer_string[:index]
    next_string = answer_string[index:]
    name, answer_type, answer_class, ttl, data_length, address = unpack(">HHHIH4s", now)
    return Answer(name, answer_type, answer_class, ttl, data_length, address), next_string

def find_answer(answer_string, count):
    answer_list = []
    next_string = answer_string
    for _ in range(count):
        answer, next_string = analysis_answer(next_string)
        answer_list.append(answer)
    return answer_list, next_string


##########  Authoritative Nameserver  ##########
def analysis_auth(auth_string):
    index = 2 + 2 + 2 + 4 + 2
    now = auth_string[:index]
    name, auth_type, auth_class, ttl, data_length = unpack(">HHHIH", now)
    now = auth_string[index:index+data_length]
    name_server = unpack(">{}s".format(data_length), now)
    next_string = auth_string[index+data_length:]
    return AuthNameServer(name, auth_type, auth_class, ttl, data_length, name_server), next_string

def find_auth_nameserver(auth_string, count):
    auth_list = []
    next_string = auth_string
    for _ in range(count):
        auth, next_string = analysis_auth(next_string)
        auth_list.append(auth)
    return auth_list, next_string

##########  Additional Records  ##########
def analysis_addit(addit_string):
    index = 2 + 2 + 2 + 4 + 2 + 4
    now = addit_string[:index]
    next_string = addit_string[index:]
    name, addit_type, addit_class, ttl, data_length, address = unpack(">HHHIHI", now)
    return AdditionalRecord(name, addit_type, addit_class, ttl, data_length, address), next_string

def find_additional_record(addit_string, count):
    addit_list = []
    next_string = addit_string
    for _ in range(count):
        addit, next_string = analysis_addit(next_string)
        addit_list.append(addit)
    return addit_list, next_string


def parse(data):
    global remain_size
    d_header, d_payload = first_parse(data)
    d_header.queries, d_payload = find_query(d_payload, d_header.questions)
    d_header.answers, d_payload = find_answer(d_payload, d_header.answer_RRs)
    d_header.authoritative_nameservers, d_payload = find_auth_nameserver(d_payload, d_header.authority_RRs)
    d_header.additional_records, d_payload = find_additional_record(d_payload, d_header.additional_RRs)

    remain_size = len(d_payload)
    return d_header, d_payload