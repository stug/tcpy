import math
import random
import socket
import subprocess
import struct
from contextlib import contextmanager
from dataclasses import dataclass
from dataclasses import field
from enum import Enum

from tcpy.ip import send_ip_packet
from tcpy.ip import listen_for_ip_packets
from tcpy.util import checksum
from tcpy.util import get_interface_ip  # TODO: remove when hack below is gone
from tcpy.util import human_readable_ip_from_int


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
    window_size: int = 100  # TODO
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


@contextmanager
def _block_tcp_port(port_number):
    """Set up an iptables rule to prevent the kernel from responding to TCP
    segments on the specified port number.  Without this the kernel sends RST
    in response to incoming segments for connections it did not initiate.
    Implemented as a contextmanager so that we make sure we remove the iptables
    rule afterwards.
    """
    iptables_rule = [
        '-p' 'tcp',
        '--destination-port', str(port_number),
        '-j', 'DROP',
    ]
    append_cmd = ['iptables', '-A' 'INPUT'] + iptables_rule
    append_result = subprocess.run(append_cmd, capture_output=True)
    try:
        yield
    finally:
        delete_cmd = ['iptables', '-D', 'INPUT'] + iptables_rule
        delete_result = subprocess.run(delete_cmd, capture_output=True)


class TcpConnection:

    def __init__(self, sock, source_ip, destination_ip, destination_port):
        self.sock = sock
        self.source_ip = get_interface_ip(sock.getsockname()[0])  # TODO: this is a hack
        self.source_port = None
        self.destination_ip = destination_ip
        self.destination_port = destination_port

        self.window_size = 65535

        self._next_sequence_number = random.getrandbits(32)
        self.other_sequence_number = None
        self.last_acked_by_them = None
        self.last_acked_by_us = 0
        self.state = TcpState.CLOSED

    def _send_segment(self, tcp_segment):
        send_ip_packet(
            sock=self.sock,
            protocol=socket.IPPROTO_TCP,
            destination_ip=self.destination_ip,
            payload=tcp_segment.to_raw(),
        )

    def _make_segment(self, **kwargs):
        sequence_number = self._next_sequence_number
        payload = kwargs.get('payload', b'')

        sequence_number_increment = len(payload)
        if sequence_number_increment == 0:
            # sequence number is expected to increment by 1 for SYN and FIN
            # segments even if they are empty
            if kwargs.get('syn', False) or kwargs.get('fin', False):
                sequence_number_increment = 1
        self._next_sequence_number += sequence_number_increment

        return TcpSegment(
            source_ip=self.source_ip,
            source_port=self.source_port,
            destination_ip=self.destination_ip,
            destination_port=self.destination_port,
            window_size=self.window_size,  # TODO: sliding window
            sequence_number=sequence_number,
            ack_number=self.last_acked_by_us,
            ack=self.last_acked_by_us > 0,
            **kwargs,
        )

    def _ack_received_segment(self, received_segment):
        print(f'acking segment {received_segment}')
        self.last_acked_by_us = received_segment.sequence_number + \
            len(received_segment.payload) + 1

        # we always ack as long as self.last_acked_by_us > 0, so just send a
        # segment
        ack_segment = self._make_segment()
        self._send_segment(ack_segment)

    def _listen_for_segments(self):
        for packet in listen_for_ip_packets(
            sock=self.sock,
            source_ip=self.destination_ip,
            destination_ip=self.source_ip,
            protocol=socket.IPPROTO_TCP,
        ):
            received_segment = TcpSegment.from_raw(packet.payload)
            print(f'Received segment inside tcp code with payload: {received_segment.payload}')
            if received_segment.destination_port == self.source_port:
                if received_segment.rst:
                    raise Exception(
                        f'Other side sent RST!  Full packet: {received_segment}',
                    )
                yield received_segment

    @contextmanager
    def connect(self):
        with socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_STREAM
        ) as tcp_sock:
            tcp_sock.bind((human_readable_ip_from_int(self.source_ip), 0))
            self.source_port = tcp_sock.getsockname()[1]

            with _block_tcp_port(self.source_port):
                syn_segment = self._make_segment(syn=True)
                self._send_segment(syn_segment)
                self.state = TcpState.SYN_SENT
                self._receive_until_state(TcpState.ESTABLISHED)
                yield
                self.close()

    def listen(self):
        raise NotImplementedError

    def send(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        assert isinstance(data, bytes), 'TcpConnection can only send str, bytes'

        segment = self._make_segment(payload=data, psh=True)
        self._send_segment(segment)

    def receive(self):
        for received_segment in self._listen_for_segments():
            if received_segment.fin:
                self.state = TcpState.CLOSE_WAIT
            self._ack_received_segment(received_segment)
            yield received_segment.payload

    def close(self):
        # TODO: handle checking last_acked before sending?
        if self.state in (TcpState.LISTEN, TcpState.SYN_SENT):
            self.state = TcpState.CLOSED
            return
        elif self.state in (
            TcpState.SYN_RECEIVED,
            TcpState.ESTABLISHED,
            TcpState.CLOSE_WAIT,
        ):
            fin_segment = self._make_segment(fin=True)
            self._send_segment(fin_segment)
            if self.state == TcpState.CLOSE_WAIT:
                self.state = TcpState.LAST_ACK
            else:
                self.state = TcpState.FIN_WAIT_1

            self._receive_until_state(TcpState.CLOSED)
        else:
            raise Exception(f'Cannot close when in state {self.state}')

    def _receive_until_state(self, desired_state):
        # do this check first before listening so that we don't recv a packet
        # we aren't going to act on
        if self.state == desired_state:
            return

        for received_segment in self._listen_for_segments():
            # TODO: make sure we aren't falling behind
            self.other_sequence_number = received_segment.sequence_number
            if self.state == TcpState.SYN_SENT:
                self._handle_syn_sent(received_segment)
            elif self.state == TcpState.ESTABLISHED:
                self._handle_established(received_segment)
            elif self.state == TcpState.FIN_WAIT_1:
                self._handle_fin_wait_1(received_segment)
            elif self.state == TcpState.FIN_WAIT_2:
                self._handle_fin_wait_2(received_segment)
            elif self.state == TcpState.CLOSING:
                self._handle_closing(received_segment)
            elif self.state == TcpState.CLOSE_WAIT:
                self._handle_close_wait(received_segment)
            elif self.state == TcpState.LAST_ACK:
                self._handle_last_ack(received_segment)
            else:
                raise Exception(f'Cannot handle state {self.state}')

            if self.state == TcpState.TIME_WAIT:
                # Sockets usually wait around a minute before moving closing,
                # but given that this is implemented so that each program runs
                # its own TCP state machine, we don't want to wait 60s before
                # ending the program
                self.state = TcpState.CLOSED

            if self.state == desired_state:
                return

    def _handle_syn_sent(self, received_segment):
        if not received_segment.ack and not received_segment.syn:
            raise Exception(f'Got unexpected response to SYN: {received_segment}')
        if received_segment.ack:
            # TODO: validate that the ACK is for the SYN
            self.last_acked_by_them = max(
                received_segment.ack_number,
                self.last_acked_by_them or 0,
            )
        if received_segment.syn:
            if self.last_acked_by_them is None:
                raise Exception(
                    'Received SYN in response to SYN.  Cannot currently '
                    'handle simultaneous open.'
                )
            self._ack_received_segment(received_segment)
            self.state = TcpState.ESTABLISHED

    def _handle_established(self, received_segment):
        if received_segment.fin:
            self._ack_received_segment(received_segment)
            self.state = TcpState.CLOSE_WAIT
        else:
            raise Exception(
                f'Cannot handle receiving data or flags other than FIN when in '
                f'{self.state}.  Received {received_segment}'
            )

    def _handle_fin_wait_1(self, received_segment):
        # TODO: validate that ACK is for FIN -- might need to keep track of
        # sequence number of FINs/SYNs so that we can test this -- can't
        # guarantee that it's the last segment even with window size 1 (e.g. in
        # case where we receive FIN after having sent FIN -- need to ACK their
        # FIN possibly before receiving ACK for our FIN
        if received_segment.fin:
            self._ack_received_segment(received_segment)
            self.state = TcpState.CLOSING

            if received_segment.ack:
                self.last_acked_by_them = max(
                    received_segment.ack_number,
                    self.last_acked_by_them or 0,
                )
                self.state = TcpState.TIME_WAIT
        elif received_segment.ack:
            self.last_acked_by_them = max(
                received_segment.ack_number,
                self.last_acked_by_them or 0,
            )
            self.state = TcpState.FIN_WAIT_2
        else:
            raise Exception(
                f'Cannot handle receiving data while in FIN_WAIT_1.  Got '
                f'{received_segment}'
            )

    def _handle_fin_wait_2(self, received_segment):
        if received_segment.fin:
            self._ack_received_segment(received_segment)
            self.state = TcpState.TIME_WAIT  # TODO: set a timer?
        else:
            raise Exception(
                f'Cannot handle receiving data while in FIN_WAIT_2.  Got '
                f'{received_segment}'
            )

    def _handle_closing(self, received_segment):
        # TODO: validate that ACK is for FIN
        if received_segment.ack:
            self.last_acked_by_them = max(
                received_segment.ack_number,
                self.last_acked_by_them or 0,
            )
            self.state = TcpState.TIME_WAIT  # TODO: set a timer?

    def _handle_close_wait(self, received_segment):
        # TODO: or can we receive data here?
        raise Exception(
            f'Received segment when in CLOSE_WAIT: {received_segment}'
        )

    def _handle_last_ack(self, received_segment):
        # TODO: validate ack number
        if received_segment.ack:
            self.last_acked_by_them = max(
                received_segment.ack_number,
                self.last_acked_by_them or 0,
            )
            self.state = TcpState.CLOSED
        else:
            raise Exception(
                f'Received segment when in LAST_ACK: {received_segment}'
            )
