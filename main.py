import re
import socket
from pprint import pprint

from dnslib import DNSRecord, DNSQuestion, RR, QTYPE, A

REDIRECT_DNS_IP = "192.168.1.1"

HOST_IP = '127.0.0.1'
HOST_PORT = 53
MSS = 1024
RESPONSE_TTL = 60


def print_log(dns_record: DNSRecord, qname: str, matched_wildcard: str | None, is_redirected: bool = False):
    def resources_types_to_str(resources: list[RR]) -> str:
        map_f = lambda x: QTYPE[x.qtype if isinstance(x, DNSQuestion) else x.rtype]
        return ",".join((map(map_f, resources)))

    def limit_str(s: str, maxlen: int) -> str:
        if len(s) > maxlen:
            return s[:maxlen - 2] + ".."
        return s

    qtypes_str = resources_types_to_str(dns_record.questions)
    atypes_str = resources_types_to_str(dns_record.rr)

    if dns_record.rr:
        ip_addr_str = str(dns_record.a.rdata)
    else:
        ip_addr_str = ""

    if not is_redirected:
        ip_addr_str += f" {{{matched_wildcard or 'M'}}})"

    ip_addr_maxlen = 35
    ip_addr_str = limit_str(ip_addr_str, ip_addr_maxlen)

    qname_maxlen = 30
    qname = limit_str(qname, qname_maxlen)

    atypes_maxlen = 15
    atypes_str = limit_str(atypes_str, atypes_maxlen)

    print(f"{qtypes_str:<5} {qname:<{qname_maxlen}} = {ip_addr_str:<{ip_addr_maxlen}} | ({qtypes_str:<5} -> {atypes_str:<{atypes_maxlen}})", end="")

    if is_redirected:
        print(f" | -> {REDIRECT_DNS_IP}")
    else:
        print()


def match_by_any_wildcard(wildcard_dict: dict[str, str], match_qname: str):
    # import pdb; pdb.set_trace()
    for (i_wildcard, i_ip) in wildcard_dict.items():
        regex_str_i = f"^{i_wildcard}$" \
            .replace(".", r"\.") \
            .replace("*", ".*")

        if re.compile(regex_str_i).match(match_qname):
            return i_wildcard, i_ip

    return None, None


def handle_dns_request(data: bytes, _: str):
    dns_resp = DNSRecord.parse(data)

    dns_question: DNSQuestion = dns_resp.questions[0]
    qname = str(dns_question.qname)[:-1]  # Remove "." in the end

    is_redirected = False

    matched_wildcard, matched_ip = match_by_any_wildcard(wildcard_match_table, qname)

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

    print_log(dns_resp, qname, matched_wildcard, is_redirected)
    return response_data


def server_main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST_IP, HOST_PORT))

    print(f"BIND: {HOST_IP}:{HOST_PORT}")

    while True:
        data, addr = sock.recvfrom(MSS)
        response = handle_dns_request(data, addr)

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
            if any(s in match_str for s in ["*", "?", "("]):
                wildcard_match_table[match_str] = ip
            else:
                exact_match_table[match_str] = ip

    pprint(exact_match_table, width=1)
    pprint(wildcard_match_table, width=1)

    server_main()
