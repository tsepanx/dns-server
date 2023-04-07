import socket
import struct
from dataclasses import dataclass
from typing import Literal

import dnslib


@dataclass
class DNSQuestionIPv4:
    domain_name: str
    query_type: Literal["A", "AAAA"]


@dataclass
class DNSAnswerIPv4:
    domain_name: str
    query_type: Literal["A", "AAAA"]

    ttl: int
    ip_addr: str


@dataclass
class DNSQueryIPv4:
    transaction_id: int
    flags: int
    questions_count: int
    answers_count: int
    authority_count: int
    additional_count: int

    questions: list[DNSQuestionIPv4] | None
    answers: list[DNSAnswerIPv4] | None
    # authorities: list[DNSAuthorityIPv4] | None
    # additional: list[...] | None


def parse_domain(data: bytes, ptr: int) -> (str, int):
    domain_parts = []
    while data[ptr] != 0:
        next_part_len = data[ptr]
        domain_parts.append(data[ptr + 1: ptr + next_part_len + 1])
        ptr += next_part_len + 1

    domain_name = ".".join(map(lambda x: x.decode("utf-8"), domain_parts))
    return domain_name, ptr


def parse_query(data: bytes) -> DNSQueryIPv4:
    fields = struct.Struct('!HHHHHH').unpack(data[:12])
    query_obj = DNSQueryIPv4(*fields)

    ptr = 0

    for i in range(query_obj.questions_count):
        qname, ptr = parse_domain(data, ptr)
        qtype = struct.unpack('!H', data[ptr + 1:ptr + 3])[0]

        question = DNSQuestionIPv4(domain_name=qname, query_type=qtype)
        query_obj.questions.append(question)
    for i in range(query_obj.answers_count):
        atype = struct.unpack('!H', response[ptr:ptr + 2])[0]
        if atype == 1:  # Type A record
            answer_length = struct.unpack('!H', response[ptr + 10:ptr + 12])[0]
            answer = response[ptr + 12:ptr + 12 + answer_length]
            ip_addr = socket.inet_ntoa(answer)

        answer = DNSAnswerIPv4()

    return query_obj


if __name__ == '__main__':
    response = b'#\x1c\x81\x80\x00\x01\x00\x01\x00\x03\x00\x02\tarchlinux\x03org\x00\x00\x01\x00\x01\xc0\x0c\x00\x01' \
               b'\x00\x01\x00\x00\x0e\x10\x00\x04_\xd9\xa3\xf6\xc0\x0c\x00\x02\x00\x01\x00\x00\x04\x8c\x00\x19' \
               b'\x08hydrogen\x02ns\x07hetzner\x03com\x00\xc0\x0c\x00\x02\x00\x01\x00\x00\x04\x8c\x00\x16\x06helium' \
               b'\x02ns\x07hetzner\x02de\x00\xc0\x0c\x00\x02\x00\x01\x00\x00\x04\x8c\x00\t\x06oxygen\xc0D\xc0\x82\x00' \
               b'\x01\x00\x01\x00\x029\xc8\x00\x04X\xc6\xe5\xc0\xc0;\x00\x01\x00\x01\x00\x029\xc8\x00\x04\xd5\x85db '

    query = parse_query(response)
    print(query)
