import socket
import struct
from dataclasses import dataclass
from dataclasses import field

from util import get_default_route_info
from util import get_ip
from util import get_mac


# used to specify the protocol for a raw AF_PACKET socket -- tells it to give us
# ALL incoming frames (e.g. not just IP)
ETH_P_ALL = 0x3

ETH_TYPE_IP = 0x0800
ETH_TYPE_ARP = 0x0806

ARP_OPERATION_REQUEST = 1
ARP_OPERATION_REPLY = 2
ETHERNET_BROADCAST_ADDRESS = 0xFFFFFFFFFFFF


@dataclass
class EthernetFrame:
    # because struct doesn't deal with 6-byte ints, we need to represent the MAC
    # addresses as 6-byte strings which we manually convert from ints
    HEADER_FORMAT = '!6s6sH'

    destination_mac: int
    source_mac: int
    ethertype: int
    payload: bytes = field(repr=False)

    # TODO: for some reason we don't have to provide the CRC -- is that done in
    # hardware or the kernel?

    @classmethod
    def from_raw(cls, raw_frame):
        header = raw_frame[0:14]
        header_fields = struct.unpack(cls.HEADER_FORMAT, header)
        return cls(
            destination_mac=int.from_bytes(
                header_fields[0],
                byteorder='big',
                signed=False,
            ),
            source_mac=int.from_bytes(
                header_fields[1],
                byteorder='big',
                signed=False,
            ),
            ethertype=header_fields[2],
            payload=raw_frame[14:],
        )

    def to_raw(self):
        header = struct.pack(
            self.HEADER_FORMAT,
            self.destination_mac.to_bytes(6, byteorder='big'),
            self.source_mac.to_bytes(6, byteorder='big'),
            self.ethertype,
        )
        # payload is expected to already be in network order
        return header + self.payload


@dataclass
class ArpPacket:
    FORMAT = '!HHBBH6sL6sL'
    PACKET_BYTES = 28

    operation: int
    sender_hardware_address: int
    sender_protocol_address: int
    target_hardware_address: int
    target_protocol_address: int
    hardware_type: int = 1  # ethernet
    protocol_type: int = ETH_TYPE_IP
    hardware_address_length: int = 6  # mac address is 6 bytes
    protocol_address_length: int = 4  # ip address is 4 bytes

    @classmethod
    def from_raw(cls, raw_packet):
        # throw away extra bytes at the end -- not sure what these are. CRC +
        # interframe gap...?
        fields = struct.unpack(cls.FORMAT, raw_packet[:cls.PACKET_BYTES])
        return cls(
            hardware_type=fields[0],
            protocol_type=fields[1],
            hardware_address_length=fields[2],
            protocol_address_length=fields[3],
            operation=fields[4],
            sender_hardware_address=int.from_bytes(
                fields[5],
                byteorder='big',
                signed=False
            ),
            sender_protocol_address=fields[6],
            target_hardware_address=int.from_bytes(
                fields[7],
                byteorder='big',
                signed=False,
            ),
            target_protocol_address=fields[8],
        )

    def to_raw(self):
        return struct.pack(
            self.FORMAT,
            self.hardware_type,
            self.protocol_type,
            self.hardware_address_length,
            self.protocol_address_length,
            self.operation,
            self.sender_hardware_address.to_bytes(6, byteorder='big'),
            self.sender_protocol_address,
            self.target_hardware_address.to_bytes(6, byteorder='big'),
            self.target_protocol_address,
        )


def arp_lookup_for_ip(sock, ip, source_mac, source_ip):
    """sock must be a RAW AF_PACKET socket.  ip must be an int"""
    arp_packet = ArpPacket(
        operation=ARP_OPERATION_REQUEST,
        sender_hardware_address=source_mac,
        sender_protocol_address=source_ip,
        target_hardware_address=0,
        target_protocol_address=ip,
    )
    ethernet_frame = EthernetFrame(
        destination_mac=ETHERNET_BROADCAST_ADDRESS,
        source_mac=source_mac,
        ethertype=ETH_TYPE_ARP,
        payload=arp_packet.to_raw()
    )
    raw_ethernet_frame = ethernet_frame.to_raw()
    sock.send(raw_ethernet_frame)

    # TODO: maybe add some sort of timeout on this
    while True:
        raw_frame, address = sock.recvfrom(65536)
        parsed_frame = EthernetFrame.from_raw(raw_frame)
        if parsed_frame.ethertype == ETH_TYPE_ARP:
            parsed_arp_packet = ArpPacket.from_raw(parsed_frame.payload)
            return parsed_arp_packet.sender_hardware_address
