import re
import socket

from pprint import pprint
from dnslib import DNSRecord, DNSQuestion, RR, QTYPE, A

from utils import print_log, REDIRECT_DNS_IP, HOST_IP, HOST_PORT, MSS, RESPONSE_TTL


def match_by_any_regex(regex_dict: dict[str, str], match_qname: str):
    for (i_regex, i_ip) in regex_dict.items():
        regex_str_i = f"^{i_regex}$" \
            .replace(".", r"\.") \
            .replace("*", ".*")

        if re.compile(regex_str_i).match(match_qname):
            return i_regex, i_ip

    return None, None


def handle_dns_request(data: bytes, _: str):
    dns_resp = DNSRecord.parse(data)

    dns_question: DNSQuestion = dns_resp.questions[0]
    qname = str(dns_question.qname)[:-1]  # Remove "." in the end

    is_redirected = False
    matched_regex, matched_ip = match_by_any_regex(regex_match_table, qname)

    if matched_ip or qname in exact_match_table:
        matched_ip_addr = matched_ip or exact_match_table[qname]

        reply = dns_resp.reply()

        reply.add_answer(RR(qname, QTYPE.A, rdata=A(matched_ip_addr), ttl=RESPONSE_TTL))

        response_data = reply.pack()
        dns_resp = reply
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
    exact_match_table: dict[str, str] = dict()
    regex_match_table: dict[str, str] = dict()

    with open("./custom_hosts", "r") as fin:
        lines = filter(lambda x: not x.startswith("#"), fin.readlines())
        lines = map(str.strip, lines)
        lines = filter(lambda x: x != "", lines)
        entries_list = map(str.split, list(lines))

        for (ip, match_str) in entries_list:
            if any(s in match_str for s in ["*", "?", "("]):
                regex_match_table[match_str] = ip
            else:
                exact_match_table[match_str] = ip

    pprint(exact_match_table, width=1)
    pprint(regex_match_table, width=1)

    server_main()
