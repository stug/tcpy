import struct
from dataclasses import dataclass
from dataclasses import field


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
