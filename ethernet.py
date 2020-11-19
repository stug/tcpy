import socket
import struct
from dataclasses import dataclass
from dataclasses import field


# ether type for IP
IP_ETH_TYPE = socket.htons(0x0800)


@dataclass
class EthernetFrame:
    HEADER_FORMAT = '!6s6sH'

    destination_mac: bytes
    source_mac: bytes
    ethertype: int
    payload: bytes = field(repr=False)

    @classmethod
    def from_raw(cls, raw_frame):
        header = raw_frame[0:14]
        header_fields = struct.unpack(cls.HEADER_FORMAT, header)
        return cls(
            destination_mac=header_fields[0],
            source_mac=header_fields[1],
            ethertype=header_fields[2],
            payload=raw_frame[14:],
        )

    def to_raw(self):
        raise NotImplementedError
