import re
import socket
from dataclasses import dataclass

from dnslib import (
    QTYPE,
    RR,
    DNSQuestion,
    DNSRecord,
)

DEFAULT_DNS_IP = "192.168.1.1"
HOST_IP = "127.0.0.1"
DNS_PORT = 53
MSS = 1024
RESPONSE_TTL = 60


class RedirectToDefaultServer(Exception):
    pass


@dataclass
class HandleResult:
    response_record: DNSRecord
    matched_regex: str | None


def send_and_recv_data(data: bytes, target_host: str, target_port: int) -> bytes:
    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_sock.sendto(data, (target_host, target_port))

    response_data, _ = dns_sock.recvfrom(MSS)
    return response_data


def get_query_domain(request_dns_record: DNSRecord) -> str:
    dns_question: DNSQuestion = request_dns_record.questions[0]
    qname = str(dns_question.qname)[:-1]  # Remove "." in the end

    return qname


def print_log(
    dns_record: DNSRecord, qname: str, matched_regex: str | None, is_redirected: bool = False
):
    def resources_types_to_str(resources: list[RR]) -> str:
        map_f = lambda x: QTYPE[x.qtype if isinstance(x, DNSQuestion) else x.rtype]
        return ",".join((map(map_f, resources)))

    def limit_str(s: str, maxlen: int) -> str:
        if len(s) > maxlen:
            return s[: maxlen - 2] + ".."
        return s

    qtypes_str = resources_types_to_str(dns_record.questions)
    atypes_str = resources_types_to_str(dns_record.rr)

    answers_ipv4 = list(filter(lambda x: x.rtype == QTYPE.A, dns_record.rr))
    if answers_ipv4:
        resp_ip = str(answers_ipv4[0].rdata)
    else:
        resp_ip = ""

    resp_ip_maxlen = 25
    resp_ip = limit_str(resp_ip, resp_ip_maxlen)

    matched_regex_maxlen = 30
    if is_redirected:
        matched_regex = ""
    else:
        matched_regex = limit_str(matched_regex, matched_regex_maxlen)

    qname_maxlen = 30
    qname = limit_str(qname, qname_maxlen)

    atypes_maxlen = 30
    atypes_str = limit_str(atypes_str, atypes_maxlen)

    print(
        # f"{qtypes_str:<5} "
        f"{qname:<{qname_maxlen}} = "
        f"{resp_ip:<{resp_ip_maxlen}} | "
        f"{matched_regex:<{matched_regex_maxlen}} | "
        f"{qtypes_str:<5} -> {atypes_str:<{atypes_maxlen}}",
        # end="",
    )


def match_by_any_regex(regex_dict: dict[str, str], match_by: str):
    """
    If matched any of key (regex) in dict, return corresponding value
    :param regex_dict: f.e.:
        {
            r"(www\.)?google\.c*": "216.239.38.120",
            "a.*\.com": "0.0.0.0"
        }
    :param match_by:
        match string, by which to match every regex
    :return: dict's item (key, value) if matched any, otherwise (None, None)
    """
    for i_regex, i_res in regex_dict.items():
        if re.compile(i_regex).match(match_by):
            return i_regex, i_res

    return None, None


def build_match_table(file_lines: list[str]) -> dict[str, str]:
    match_table = dict()

    lines = filter(lambda x: not x.startswith("#"), file_lines)
    lines = map(str.strip, lines)
    lines = filter(lambda x: x != "", lines)

    entries_list = map(str.split, list(lines))

    for match_res_i, match_regex_i in entries_list:
        match_regex_i = f"^{match_regex_i}$"
        match_regex_i = match_regex_i.replace(".", r"\.")
        match_regex_i = match_regex_i.replace("*", ".*")

        match_table[match_regex_i] = match_res_i

    return match_table


def print_match_table(match_table: dict[str, str]):
    row_1_maxlen = 25
    row_2_maxlen = 20
    print(f"{'REGEX':<{row_1_maxlen}} | {'MATCH':<{row_2_maxlen}}\n")
    print(
        "\n".join([f"{a:<{row_1_maxlen}} | {b:<{row_2_maxlen}}" for (a, b) in match_table.items()])
    )
    print()
