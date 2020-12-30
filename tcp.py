import math
import random
import socket
import struct
from dataclasses import dataclass
from dataclasses import field
from enum import Enum

from ip import send_ip_packet
from ip import listen_for_ip_packets
from util import checksum
from util import get_interface_ip  # TODO: remove when hack below is gone
from util import human_readable_ip_from_int


class TcpState(Enum):
    CLOSED = 0
    SYN_SENT = 1
    LISTEN = 2
    SYN_RECEIVED = 3
    ESTABLISHED = 4
    FIN_WAIT_1 = 5
    FIN_WAIT_2 = 6
    CLOSING = 7
    TIME_WAIT = 8
    CLOSE_WAIT = 9
    LAST_ACK = 10


@dataclass
class TcpSegment:
    # omits the options field since its length is variable and we need to parse
    # the data offset field to know how big it is
    HEADER_FORMAT = '!HHIIBBHHH'

    source_port: int = 0
    destination_port: int = 0
    sequence_number: int = 0
    ack_number: int = 0
    data_offset: int = 0
    ns: bool = False
    cwr: bool = False
    ece: bool = False
    urg: bool = False
    ack: bool = False
    psh: bool = False
    rst: bool = False
    syn: bool = False
    fin: bool = False
    window_size: int = 1  # TODO
    checksum: int = 0
    urgent_pointer: int = 0
    options: bytes = b''
    payload: bytes = field(repr=False, default=b'')

    # these are needed on outgoing segments to compute the checksum
    source_ip: int = 0
    destination_ip: int = 0

    @classmethod
    def from_raw(cls, raw_segment):
        header = raw_segment[0:20]
        header_fields = struct.unpack(cls.HEADER_FORMAT, header)

        data_offset = header_fields[4] >> 4
        options_field_size = (data_offset - 5) * 4
        
        return cls(
            source_port=header_fields[0],
            destination_port=header_fields[1],
            sequence_number=header_fields[2],
            ack_number=header_fields[3],
            data_offset=data_offset,
            ns=bool(header_fields[4] & 0x1),
            cwr=bool(header_fields[5] & 0x80),
            ece=bool(header_fields[5] & 0x40),
            urg=bool(header_fields[5] & 0x20),
            ack=bool(header_fields[5] & 0x10),
            psh=bool(header_fields[5] & 0x08),
            rst=bool(header_fields[5] & 0x04),
            syn=bool(header_fields[5] & 0x02),
            fin=bool(header_fields[5] & 0x01),
            window_size=header_fields[6],
            checksum=header_fields[7],
            urgent_pointer=header_fields[8],
            options=raw_segment[20:20+options_field_size],
            payload=raw_segment[20+options_field_size:],
        )

    def __post_init__(self):
        if self.data_offset == 0:
            self.data_offset = 5 + math.ceil(len(self.options) / 4)

        # checksum must be added last so that it has final field values
        if self.checksum == 0 :
            self.checksum = self._compute_checksum()

    def _compute_checksum(self):
        assert self.source_ip != 0, 'Must set source ip!'
        assert self.destination_ip != 0, 'Must set destination ip!'

        raw_segment = self.to_raw()
        ip_pseudo_header = struct.pack(
            '!LLHH',
            self.source_ip,
            self.destination_ip,
            socket.IPPROTO_TCP,
            len(raw_segment),
        )
        fake_packet = ip_pseudo_header + raw_segment
        return checksum(fake_packet)

    def to_raw(self):
        data_offset_ns = (self.data_offset << 4) + int(self.ns)
        other_flags = (
            (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4)
            + (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + int(self.fin)
        )
        assert len(self.options) == 0, 'Cannot handle sending TCP segments with options right now'
        header = struct.pack(
            self.HEADER_FORMAT,
            self.source_port,
            self.destination_port,
            self.sequence_number,
            self.ack_number,
            data_offset_ns,
            other_flags,
            self.window_size,
            self.checksum,
            self.urgent_pointer,
        )

        # as elsewhere, the payload is assumed to be raw bytes in network order
        return header + self.options + self.payload


class TcpConnection:

    def __init__(self, sock, source_ip, destination_ip, destination_port):
        self.sock = sock
        self.source_ip = get_interface_ip(sock.getsockname()[0])  # TODO: this is a hack
        self.source_port = None
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.sequence_number = random.getrandbits(32)
        self.state = TcpState.CLOSED

    def _send_tcp_segment(self, tcp_segment):
        send_ip_packet(
            sock=self.sock,
            protocol=socket.IPPROTO_TCP,
            destination_ip=self.destination_ip,
            payload=tcp_segment.to_raw(),
        )

    def connect(self):
        with socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_STREAM
        ) as tcp_sock:
            tcp_sock.bind((human_readable_ip_from_int(self.source_ip), 0))
            self.source_port = tcp_sock.getsockname()[1]
            self._connect()

    def _connect(self):
        syn_segment = TcpSegment(
            source_ip=self.source_ip,
            source_port=self.source_port,
            destination_ip=self.destination_ip,
            destination_port=self.destination_port,
            sequence_number=self.sequence_number,
            syn=True,
        )
        self._send_tcp_segment(syn_segment)
        self.state = TcpState.SYN_SENT
        for packet in listen_for_ip_packets(
            sock=self.sock,
            source_ip=self.destination_ip,
            destination_ip=self.source_ip,
            protocol=socket.IPPROTO_TCP,
        ):
            received_segment = TcpSegment.from_raw(packet.payload)
            print(received_segment)
