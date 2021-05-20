import random
import struct
from dataclasses import dataclass

from tcpy.util import checksum


ICMP_TYPE_ECHO_REPLY = 0
ICMP_TYPE_ECHO_REQUEST = 8


@dataclass
class IcmpDatagram:
    # this is just the first 3 fields since the rest varies with the type & code
    HEADER_FORMAT = '!BBH4s'

    type: int
    code: int
    checksum: int = 0
    rest_of_header: bytes = b''
    payload: bytes = b''

    @classmethod
    def from_raw(cls, raw_datagram):
        header = raw_datagram[0:8]
        header_fields = struct.unpack(cls.HEADER_FORMAT, header)

        return cls(
            type=header_fields[0],
            code=header_fields[1],
            checksum=header_fields[2],
            rest_of_header=header_fields[3],
            payload=raw_datagram[8:],
        )

    def __post_init__(self):
        if self.checksum == 0:
            self.checksum = checksum(self.to_raw())

    def _pack_header(self):
        return struct.pack(
            self.HEADER_FORMAT,
            self.type,
            self.code,
            self.checksum,
            self.rest_of_header,
        )

    def to_raw(self):
        return self._pack_header() + self.payload


@dataclass
class IcmpEchoRequestHeaderFields:
    FORMAT = '!HH'

    sequence_number: int
    identifier: int = 0

    def __post_init__(self):
        if self.identifier == 0:
            self.identifier = random.getrandbits(8)

    def to_raw(self):
        return struct.pack(self.FORMAT, self.identifier, self.sequence_number)
