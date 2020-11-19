import socket
import struct
import sys
from dataclasses import dataclass
from dataclasses import field


@dataclass
class IpPacket:
    HEADER_FORMAT = '!BBH2sHBBHLL'

    version: int
    ihl: int
    dscp: int
    ecn: int
    total_length: int
    identification: bytes
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    header_checksum: int
    source_ip: int
    destination_ip: int
    payload: bytes = field(repr=False)

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
            payload=raw_packet[21 : total_length],
        )

    def to_raw(self):
        raise NotImplementedError


@dataclass
class IcmpDatagram:
    # this is just the first 3 fields since the rest varies with the type & code
    HEADER_FORMAT = '!BBH'

    type: int
    code: int
    checksum: int
    remainder: bytes

    @classmethod
    def from_raw(cls, raw_datagram):
        header = raw_datagram[0:4]
        header_fields = struct.unpack(cls.HEADER_FORMAT, header)

        return cls(
            type=header_fields[0],
            code=header_fields[1],
            checksum=header_fields[2],
            remainder=raw_datagram[4:]
        )

    def to_raw(self):
        raise NotImplementedError


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
