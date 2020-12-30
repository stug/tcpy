import socket

from dns import DnsPacket
from ethernet import EthernetFrame
from icmp import IcmpDatagram
from ip import IpPacket
from tcp import TcpSegment
from udp import UdpDatagram
from util import get_raw_af_packet_socket


def main():
    sock = get_raw_af_packet_socket()
    
    # TODO: make this print things more nicely
    while True:
        try:
            raw_frame, address = sock.recvfrom(65536)
            parsed_frame = EthernetFrame.from_raw(raw_frame)
            print(parsed_frame)

            parsed_ip_packet = IpPacket.from_raw(parsed_frame.payload)
            print(parsed_ip_packet)

            if parsed_ip_packet.protocol == socket.IPPROTO_ICMP:
                parsed_icmp_datagram = IcmpDatagram.from_raw(parsed_ip_packet.payload)
                print(parsed_icmp_datagram)
            elif parsed_ip_packet.protocol == socket.IPPROTO_TCP:
                parsed_tcp_segment = TcpSegment.from_raw(parsed_ip_packet.payload)
                print(parsed_tcp_segment)
            elif parsed_ip_packet.protocol == socket.IPPROTO_UDP:
                parsed_udp_datagram = UdpDatagram.from_raw(parsed_ip_packet.payload)
                print(parsed_udp_datagram)
                if (
                    parsed_udp_datagram.source_port == 53
                    or parsed_udp_datagram.destination_port == 53
                ):
                    parsed_dns_packet = DnsPacket.from_raw(parsed_udp_datagram.payload)
                    print(parsed_dns_packet)
            else:
                print(f'Got unsupported IP Protocol: {parsed_ip_packet.protocol}')
                print(f'Raw payload: {parsed_ip_packet.payload}')

            print()

        except KeyboardInterrupt:
            break


if __name__ == '__main__':
    main()
