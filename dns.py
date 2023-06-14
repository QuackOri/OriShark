from dataclasses import dataclass
from struct import *
import functions as f

header_size = 2 + 2 + 2 + 2 + 2 + 2

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

    # # return header length
    # def __len__(self):
    #     return header_size
    
def first_parse(data):
    header = data[:header_size]
    payload = data[header_size:]
    t_id, flags, questions, ans, auth, addit = unpack('>HHHHHH', header)

    return DNSResponse(t_id, flags, questions, ans, auth, addit, [], [], [], []), payload

def parse(data):
    d_header, d_payload = first_parse(data)
    d_header.queries, d_payload = f.find_query(d_payload, d_header.questions)
    d_header.answers, d_payload = f.find_answer(d_payload, d_header.answer_RRs)
    d_header.authoritative_nameservers, d_payload = f.find_auth_nameserver(d_payload, d_header.authority_RRs)
    d_header.additional_records, d_payload = f.find_additional_record(d_payload, d_header.additional_RRs)

    return d_header, d_payload