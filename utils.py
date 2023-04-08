from dnslib import DNSRecord, RR, QTYPE, DNSQuestion


REDIRECT_DNS_IP = "192.168.1.1"
HOST_IP = '127.0.0.1'
HOST_PORT = 53
MSS = 1024
RESPONSE_TTL = 60


def print_log(dns_record: DNSRecord, qname: str, matched_regex: str | None, is_redirected: bool = False):
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
        ip_addr_str += f" '{matched_regex or 'M'}'"

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
