import socket

from ethernet import ETH_TYPE_IP
from ethernet import EthernetFrame
from icmp import IcmpDatagram
from structs import IpPacket
from structs import TcpSegment
from structs import UdpDatagram


def main():
    # raw AF_PACKET socket gets raw link layer frames -- requires sudo
    sock = socket.socket(
        family=socket.AF_PACKET,
        type=socket.SOCK_RAW,
        proto=socket.htons(ETH_TYPE_IP),
    )
    
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
            else:
                print(f'Got unsupported IP Protocol: {parsed_ip_packet.protocol}')
                print(f'Raw payload: {parsed_ip_packet.payload}')

            print()

        except KeyboardInterrupt:
            break


if __name__ == '__main__':
    main()
