import socket
import struct
from pprint import pprint

from dnslib import DNSRecord, DNSQuestion, RR, QTYPE, A

from utils import parse_query

DNS_SERVER_ADDRESS = '127.0.0.1'
BLOCK_IP_ADDR = "0.0.0.0"

REDIRECT_DNS_IP = "192.168.1.1"
DNS_PORT = 53
MSS = 1024


def print_log(ip_addr, qtype, qname, is_redirected: bool = False):
    print(f"{ip_addr:<40} {QTYPE[qtype]:<20} {qname:<30}", end="")

    if is_redirected:
        print(f" -> {REDIRECT_DNS_IP}")
    else:
        print()


def handle_dns_request(data: bytes, _: str):
    dns_record = DNSRecord.parse(data)

    dns_question: DNSQuestion = dns_record.questions[0]
    qtype = dns_question.qtype
    qname = str(dns_question.qname)[:-1]  # Remove "." in the end

    # import pdb;pdb.set_trace()
    if qname in exact_match_table:
        ip_addr = exact_match_table[qname]

        # print(qtype)
        reply = dns_record.reply()
        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, qtype, rdata=A(ip_addr), ttl=60))

            print_log(ip_addr, qtype, qname)
            return reply.pack()
        else:
            print_log("=== NO ANSWERS ===", qtype, qname)
            return reply.pack()
    else:
        # Redirect to default DNS server
        dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_sock.sendto(data, (REDIRECT_DNS_IP, DNS_PORT))
        response, _ = dns_sock.recvfrom(MSS)

        dns_resp = DNSRecord.parse(response)
        ip_addr = str(dns_resp.a.rdata)

        # import pdb; pdb.set_trace()

        print_log(ip_addr, qtype, qname, True)
        return response


def server_main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DNS_SERVER_ADDRESS, DNS_PORT))

    print(f"BIND: {DNS_SERVER_ADDRESS}:{DNS_PORT}")

    while True:
        data, addr = sock.recvfrom(MSS)
        response = handle_dns_request(data, addr)

        if response is None:
            print("DROPPING REQUEST")
            continue

        sock.sendto(response, addr)


if __name__ == "__main__":
    exact_match_table: dict[str, str] = dict()
    wildcard_match_table: dict[str, str] = dict()

    with open("./custom_hosts", "r") as fin:
        lines = filter(lambda x: not x.startswith("#"), fin.readlines())
        lines = map(str.strip, lines)
        lines = filter(lambda x: x != "", lines)
        entries_list = map(str.split, list(lines))

        for (ip, match_str) in entries_list:
            if "*" not in match_str:
                exact_match_table[match_str] = ip
            else:
                wildcard_match_table[match_str] = ip

    pprint(exact_match_table, width=1)
    pprint(wildcard_match_table, width=1)

    server_main()
