import socket

from dnslib import (
    QTYPE,
    RR,
    A,
    DNSQuestion,
    DNSRecord,
)

from utils import (
    DEFAULT_DNS_IP,
    DNS_PORT,
    HOST_IP,
    MSS,
    RESPONSE_TTL,
    build_match_table,
    match_by_any_regex,
    print_log,
    print_match_table,
)

match_table: dict[str, str] = dict()


def send_and_recv_data(data: bytes, target_host: str, target_port: int) -> bytes:
    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_sock.sendto(data, (target_host, target_port))

    response_data, _ = dns_sock.recvfrom(MSS)
    return response_data


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
        response_data = send_and_recv_data(data, DEFAULT_DNS_IP, DNS_PORT)

        dns_resp = DNSRecord.parse(response_data)
        is_redirected = True

    print_log(dns_resp, qname, matched_regex, is_redirected)
    return response_data


def server_main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST_IP, DNS_PORT))

    print(f"DEFAULT SERVER: {DEFAULT_DNS_IP}")
    print(f"BIND: {HOST_IP}:{DNS_PORT}\n")

    while True:
        data, addr = sock.recvfrom(MSS)
        response = handle_dns_request(data, addr)

        sock.sendto(response, addr)


if __name__ == "__main__":
    with open("./custom_hosts", "r") as fin:
        match_table = build_match_table(fin.readlines())

    print_match_table(match_table)

    server_main()
