import sys

from tcpy.tcp import TcpConnection
from tcpy.util import get_raw_af_packet_socket
from tcpy.util import human_readable_ip_to_int


def main(destination_ip, destination_port):
    sock = get_raw_af_packet_socket()
    tcp_connection = TcpConnection(
        sock=sock,
        source_ip=None,
        destination_ip=human_readable_ip_to_int(destination_ip),
        destination_port=int(destination_port),
    )
    with tcp_connection.connect():
        print('Connected!  Now closing connection!')

    print('Closed!')


main(sys.argv[1], sys.argv[2])
