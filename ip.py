import random
import struct
from dataclasses import dataclass
from dataclasses import field

from ethernet import arp_lookup_for_ip
from ethernet import send_ethernet_frame
from ethernet import EthernetFrame
from ethernet import ETH_TYPE_IP
from util import checksum
from util import get_default_route_info
from util import get_ip
from util import get_mac


IP_FLAGS_DONT_FRAGMENT = 0b010


@dataclass
class IpPacket:
    HEADER_FORMAT = '!BBHHHBBHLL'

    protocol: int
    source_ip: int
    destination_ip: int

    payload: bytes = field(repr=False)

    version: int = 4
    ihl: int = 5
    dscp: int = 0  # TODO: ok?
    ecn: int = 0  # TODO ok?
    ttl: int = 255
    header_checksum: int = 0
    flags: int = 0  # TODO: split out flags?
    fragment_offset: int = 0
    total_length: int = 0
    identification: int = 0

    @classmethod
    def from_raw(cls, raw_packet):
        # this assumes ihl = 5 (for 5 4-byte words), which it should almost always be
        header = raw_packet[0:20]
        header_fields = struct.unpack(cls.HEADER_FORMAT, header)

        version = header_fields[0] >> 4
        ihl = header_fields[0] & 0x0F
        assert ihl == 5, f'Cannot handle IP packets with ihl != 5 (got {ihl}).'

        dscp = header_fields[1] >> 2
        ecn = header_fields[1] & 0x03

        total_length = header_fields[2]

        flags = header_fields[4] >> 15
        fragment_offset = header_fields[4] & 0x1FFF

        return cls(
            version=version,
            ihl=ihl,
            dscp=dscp,
            ecn=ecn,
            total_length=total_length,
            identification=header_fields[3],
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=header_fields[5],
            protocol=header_fields[6],
            header_checksum=header_fields[7],
            source_ip=header_fields[8],
            destination_ip=header_fields[9],
            payload=raw_packet[20 : total_length],
        )

    def __post_init__(self):
        if self.identification == 0:
            self.identification = random.getrandbits(16)

        if self.total_length == 0:
            self.total_length = len(self.to_raw())

        # must be done last since the other fields affect the checksum value
        if self.header_checksum == 0:
            self.header_checksum = checksum(self._pack_header())
 
    def _pack_header(self):
        version_ihl = (self.version << 4) + self.ihl
        dscp_ecn = (self.dscp << 2) + self.ecn
        flags_fragment_offset = (self.flags << 13) + self.fragment_offset

        return struct.pack(
            self.HEADER_FORMAT,
            version_ihl,
            dscp_ecn,
            self.total_length,
            self.identification,
            flags_fragment_offset,
            self.ttl,
            self.protocol,
            self.header_checksum,
            self.source_ip,
            self.destination_ip,
        )
        
    def to_raw(self):
        # payload expected to be raw bytes in network order
        return self._pack_header() + self.payload


def send_ip_packet(sock, protocol, destination_ip, payload, flags=None):
    # TODO: this could maybe do longest prefix match to choose an interface
    # although then we would have to bind the socket here
    default_interface, gateway_ip = get_default_route_info()
    source_ip = get_ip(default_interface)
    gateway_mac = arp_lookup_for_ip(sock=sock, ip=gateway_ip)

    packet = IpPacket(
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        flags=flags,
        payload=payload,
    )
    send_ethernet_frame(sock, ETH_TYPE_IP, gateway_mac, packet.to_raw())


def listen_for_ip_packets(
    sock,
    source_ip=None,
    destination_ip=None,
    protocol=None,
):
    while True:
        raw_frame, address = sock.recvfrom(65536)
        parsed_frame = EthernetFrame.from_raw(raw_frame)
        if parsed_frame.ethertype != ETH_TYPE_IP:
            continue

        ip_packet = IpPacket.from_raw(parsed_frame.payload)
        if source_ip is not None and ip_packet.source_ip != source_ip:
            continue
        if protocol is not None and ip_packet.protocol != protocol:
            continue

        yield ip_packet
