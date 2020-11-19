import struct
from dataclasses import dataclass


ICMP_TYPE_ECHO_REPLY = 0
ICMP_TYPE_ECHO_REQUEST = 8


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


