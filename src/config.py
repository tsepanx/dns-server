import configparser

DNS_PORT = 53
MSS = 1024
CONF_FILENAME = "./dns_server.conf"

config = configparser.ConfigParser()
config.read(CONF_FILENAME)
config_dns = config["DNS"]

NAMESERVERS = config_dns["nameservers"].split(",")
HOST_IP = config_dns["host_ip"]
RESPONSE_TTL = int(config_dns["response_ttl"])

HOSTS_FILE = config_dns["hosts_file"]
