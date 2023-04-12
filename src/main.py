import logging
import socket

from dnslib import (
    QTYPE,
    RR,
    A,
    DNSRecord,
)
from dnslib.dns import DNSError

from config import (
    DNS_PORT,
    HOST_IP,
    HOSTS_FILE,
    MSS,
    NAMESERVERS,
    RESPONSE_TTL,
)
from utils import (
    RedirectToDefaultServer,
    build_match_table,
    get_query_domain,
    log_query,
    match_by_any_regex,
    match_table_str,
    send_and_recv_data,
)

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
            log_query(response_record, qname, matched_regex, is_redirected=False)
        except RedirectToDefaultServer:
            response_data = send_and_recv_data(data, NAMESERVERS[0], DNS_PORT)
            response_record = DNSRecord.parse(response_data)

            log_query(response_record, qname, None, is_redirected=True)

        sock.sendto(response_record.pack(), addr)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )

    with open(HOSTS_FILE, "r") as fin:
        match_table = build_match_table(fin.readlines())

    logger = logging.getLogger(__name__)

    logger.info(f"DEFAULT SERVER: {NAMESERVERS[0]}")
    logger.info(f"BIND: {HOST_IP}:{DNS_PORT}\n")
    logger.info(
        match_table_str(match_table)
    )

    server_main()
