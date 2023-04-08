import socket
from pprint import pprint

from dnslib import (
    QTYPE,
    RR,
    A,
    DNSQuestion,
    DNSRecord,
)

from utils import (
    HOST_IP,
    HOST_PORT,
    MSS,
    REDIRECT_DNS_IP,
    RESPONSE_TTL,
    build_match_table,
    match_by_any_regex,
    print_log,
)

match_table: dict[str, str] = dict()


def handle_dns_request(data: bytes, _: str):
    dns_resp = DNSRecord.parse(data)

    dns_question: DNSQuestion = dns_resp.questions[0]
    qname = str(dns_question.qname)[:-1]  # Remove "." in the end

    matched_regex, matched_ip = match_by_any_regex(match_table, qname)

    if matched_ip:
        reply = dns_resp.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(matched_ip), ttl=RESPONSE_TTL))

        response_data = reply.pack()
        dns_resp = reply
        is_redirected = False
    else:
        # Redirect to default DNS server
        dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_sock.sendto(data, (REDIRECT_DNS_IP, HOST_PORT))

        response_data, _ = dns_sock.recvfrom(MSS)
        dns_resp = DNSRecord.parse(response_data)
        is_redirected = True

    print_log(dns_resp, qname, matched_regex, is_redirected)
    return response_data


def server_main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST_IP, HOST_PORT))

    print(f"BIND: {HOST_IP}:{HOST_PORT}\n")

    while True:
        data, addr = sock.recvfrom(MSS)
        response = handle_dns_request(data, addr)

        sock.sendto(response, addr)


if __name__ == "__main__":
    with open("./custom_hosts", "r") as fin:
        match_table = build_match_table(fin.readlines())

    pprint(match_table, width=1)

    server_main()
