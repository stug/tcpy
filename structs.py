import socket
import struct
from dataclasses import dataclass
from dataclasses import field


@dataclass
class TcpSegment:
    # omits the options field since its length is variable and we need to parse
    # the data offset field to know how big it is
    HEADER_FORMAT = '!HHIIBBHHH'

    source_port: int
    destination_port: int
    sequence_number: int
    ack_number: int
    data_offset: int
    ns: bool
    cwr: bool
    ece: bool
    urg: bool
    ack: bool
    psh: bool
    rst: bool
    syn: bool
    fin: bool
    window_size: int
    checksum: int
    urgent_pointer: int
    options: bytes
    payload: bytes

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

    def to_raw(self):
        raise NotImplementedError


@dataclass
class UdpDatagram:
    HEADER_FORMAT = '!HHHH'

    source_port: int
    destination_port: int
    length: int
    checksum: int
    payload: bytes

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

    def to_raw(self):
        raise NotImplementedError
