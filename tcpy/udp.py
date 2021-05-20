import socket
import struct
from dataclasses import dataclass
from dataclasses import field

from tcpy.ip import listen_for_ip_packets
from tcpy.ip import send_ip_packet


@dataclass
class UdpDatagram:
    HEADER_FORMAT = '!HHHH'

    source_port: int
    destination_port: int
    payload: bytes = field(repr=False)
    length: int = 0
    checksum: int = 0

    @classmethod
    def from_raw(cls, raw_datagram):
        header = raw_datagram[0:8]
        header_fields = struct.unpack(cls.HEADER_FORMAT, header)
        return cls(
            source_port=header_fields[0],
            destination_port=header_fields[1],
            length=header_fields[2],
            checksum=header_fields[3],
            payload=raw_datagram[8:]
        )

    def __post_init__(self):
        # TODO: add a checksum, which uses a "pseudo header" containing some
        # fields from the ip header, which is annoying.
        if self.length == 0:
            self.length = len(self.to_raw())

    def to_raw(self):
        header = struct.pack(
            self.HEADER_FORMAT,
            self.source_port,
            self.destination_port,
            self.length,
            self.checksum,
        )
        # payload expected to already be in network order
        return header + self.payload


def send_udp_datagram(
    sock,
    source_port,
    destination_ip,
    destination_port,
    payload,
):
    datagram = UdpDatagram(
        source_port=source_port,
        destination_port=destination_port,
        payload=payload,
    )
    send_ip_packet(
        sock=sock,
        protocol=socket.IPPROTO_UDP,
        destination_ip=destination_ip,
        payload=datagram.to_raw(),
    )


def listen_for_udp_datagrams(
    sock,
    source_ip=None,
    source_port=None,
    destination_port=None,
):
    for packet in listen_for_ip_packets(
        sock,
        source_ip=source_ip,
        protocol=socket.IPPROTO_UDP,
    ):
        udp_datagram = UdpDatagram.from_raw(packet.payload)
        if source_port is not None and udp_datagram.source_port != source_port:
            continue
        if (
            destination_port is not None
            and udp_datagram.destination_port != destination_port
        ):
            continue

        yield udp_datagram
