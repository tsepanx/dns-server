import configparser
import socket

from dnslib import (
    QTYPE,
    RR,
    A,
    DNSRecord,
)
from dnslib.dns import DNSError

from utils import (
    DNS_PORT,
    MSS,
    RedirectToDefaultServer,
    build_match_table,
    get_query_domain,
    match_by_any_regex,
    print_log,
    print_match_table,
    send_and_recv_data,
)

HOSTS_FILENAME = "./custom_hosts"
CONF_FILENAME = "./dns_server.conf"

match_table: dict[str, str] = dict()


def handle_dns_request(request_dns_record: DNSRecord) -> (DNSRecord, str):
    qname = get_query_domain(request_dns_record)

    if request_dns_record.questions[0].qtype not in [QTYPE.A, QTYPE.AAAA]:
        print(request_dns_record.questions)

    matched_regex, matched_ip = match_by_any_regex(match_table, qname)

    if not matched_ip:
        raise RedirectToDefaultServer

    reply = request_dns_record.reply()
    reply.add_answer(RR(qname, QTYPE.A, rdata=A(matched_ip), ttl=RESPONSE_TTL))

    return reply, matched_regex


def server_main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST_IP, DNS_PORT))

    print(f"DEFAULT SERVER: {NAMESERVERS[0]}")
    print(f"BIND: {HOST_IP}:{DNS_PORT}\n")

    while True:
        data, addr = sock.recvfrom(MSS)

        try:
            request_record = DNSRecord.parse(data)
        except DNSError:
            print(f"Unknown packet received: {data, addr}")
            continue

        qname = get_query_domain(request_record)

        try:
            response_record, matched_regex = handle_dns_request(request_record)
            print_log(response_record, qname, matched_regex, is_redirected=False)
        except RedirectToDefaultServer:
            response_data = send_and_recv_data(data, NAMESERVERS[0], DNS_PORT)
            response_record = DNSRecord.parse(response_data)

            print_log(response_record, qname, None, is_redirected=True)

        sock.sendto(response_record.pack(), addr)


if __name__ == "__main__":
    with open(HOSTS_FILENAME, "r") as fin:
        match_table = build_match_table(fin.readlines())

    config = configparser.ConfigParser()
    config.read(CONF_FILENAME)

    try:
        NAMESERVERS: list[str] = config["DNS"]["nameservers"].split(",")
        HOST_IP = config["DNS"]["host_ip"]
        RESPONSE_TTL = int(config["DNS"]["response_ttl"])
    except Exception as e:
        print("Error while reading conf:", e)

    print_match_table(match_table)

    server_main()
