import socket
import sys

from dns import human_readable_ip_to_arpa_domain
from dns import parse_dns_name
from dns import perform_dns_lookup
from dns import DNS_TYPE_A
from dns import DNS_TYPE_CNAME
from dns import DNS_TYPE_PTR
from util import get_raw_af_packet_socket
from util import is_ip_string
from util import print_table


def dns_lookup(name):
    sock = get_raw_af_packet_socket()

    name = name.strip()
    if is_ip_string(name):
        record_type = DNS_TYPE_PTR
        name = human_readable_ip_to_arpa_domain(name)
    else:
        record_type = DNS_TYPE_A

    dns_response = perform_dns_lookup(sock, name, record_type)

    if dns_response.rcode == 3:
        print(f'Could not find record for {name}')
        return

    rows = [['RECORD', 'TYPE', 'VALUE']]
    for answer in dns_response.answers:
        record_name = answer.record_name.decode('utf-8')
        if answer.record_type == DNS_TYPE_A:
            record_type = 'A'
            ip_octets = [str(answer.rdata[i]) for i in range(4)]
            value = '.'.join(ip_octets)
        elif answer.record_type == DNS_TYPE_CNAME:
            record_type = 'CNAME'
            value, _ = parse_dns_name(answer.rdata, 0)
            value = value.decode('utf-8')
        elif answer.record_type == DNS_TYPE_PTR:
            record_type = 'PTR'
            value, _ = parse_dns_name(answer.rdata, 0)
            value = value.decode('utf-8')
        else:
            raise Exception(f'Unknown DNS record type {answer.record_type}')

        rows.append([record_name, record_type, value])

    print_table(rows)


if __name__ == '__main__':
    dns_lookup(sys.argv[1])
