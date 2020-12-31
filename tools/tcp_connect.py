import sys

from tcp import TcpConnection
from util import get_raw_af_packet_socket
from util import human_readable_ip_to_int


def main(destination_ip, destination_port):
    sock = get_raw_af_packet_socket()
    tcp_connection = TcpConnection(
        sock=sock,
        source_ip=None,
        destination_ip=human_readable_ip_to_int(destination_ip),
        destination_port=int(destination_port),
    )
    with tcp_connection.connect():
        import ipdb; ipdb.set_trace()
        print('established connection!')

    print('closed connection!')


main(sys.argv[1], sys.argv[2])
