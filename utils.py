import re

from dnslib import (
    QTYPE,
    RR,
    DNSQuestion,
    DNSRecord,
)

REDIRECT_DNS_IP = "192.168.1.1"
HOST_IP = "127.0.0.1"
HOST_PORT = 53
MSS = 1024
RESPONSE_TTL = 60


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

    if dns_record.rr:
        ip_addr_str = str(dns_record.a.rdata)
    else:
        ip_addr_str = ""

    if not is_redirected:
        ip_addr_str += f" '{matched_regex or 'M'}'"

    ip_addr_maxlen = 35
    ip_addr_str = limit_str(ip_addr_str, ip_addr_maxlen)

    qname_maxlen = 30
    qname = limit_str(qname, qname_maxlen)

    atypes_maxlen = 15
    atypes_str = limit_str(atypes_str, atypes_maxlen)

    print(
        f"{qtypes_str:<5} "
        f"{qname:<{qname_maxlen}} = "
        f"{ip_addr_str:<{ip_addr_maxlen}} | "
        f"({qtypes_str:<5} -> {atypes_str:<{atypes_maxlen}})",
        end="",
    )

    if is_redirected:
        print(f" | -> {REDIRECT_DNS_IP}")
    else:
        print()


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
