import sys

from tcpy.dns import get_ip_for_name
from tcpy.http import build_http_request
from tcpy.http import parse_http_url
from tcpy.http import receive_http_response
from tcpy.tcp import TcpConnection
from tcpy.util import get_raw_af_packet_socket
from tcpy.util import human_readable_ip_from_int
from tcpy.util import human_readable_ip_to_int
from tcpy.util import is_ip_string


def main(url):
    host, port, path = parse_http_url(url)
    sock = get_raw_af_packet_socket()

    if is_ip_string(host):
        host_ip = human_readable_ip_to_int(host)
        human_readable_ip = host
    else:
        host_ip = get_ip_for_name(sock, host)
        human_readable_ip = human_readable_ip_from_int(host_ip)

    tcp_connection = TcpConnection(
        sock=sock,
        source_ip=None,
        destination_ip=host_ip,
        destination_port=port,
    )
    with tcp_connection.connect():
        http_request = build_http_request(host, port, path)
        print(f'Sending following http request to {human_readable_ip}:{port}')
        print(http_request)
        tcp_connection.send(http_request)

        print('Response payloads:')
        for payload in tcp_connection.receive():
            print(payload)
            print()

        # http_response = receive_http_response(tcp_connection)
        # print('Received response:')
        # print(response.get_full_response())

    print('Connection closed')


main(sys.argv[1])
