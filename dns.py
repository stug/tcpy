import struct
from dataclasses import dataclass


@dataclass
class DnsPacket:
    HEADER_FORMAT = '!HBBHHHH'

    id: int  # TODO: autogenerate this
    qr: int 
    opcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    rcode: int
    
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    questions: list
    answers: list
    authorities: list
    additional: list

    @classmethod
    def from_raw(cls, raw_packet):
        header = raw_packet[0:struct.calcsize(cls.HEADER_FORMAT)]  # TODO: maybe don't need to do this?
        header_fields = struct.unpack(cls.HEADER_FORMAT, header)

        qr = header_fields[1] >> 7
        opcode = (header_fields[1] >> 3) & 0xF
        aa = bool((header_fields[1] >> 2) & 1)
        tc = bool((header_fields[1] >> 1) & 1)
        rd = bool(header_fields[1] & 1)

        ra = bool(header_fields[2] >> 7)
        rcode = header_fields[2] & 0xF

        return cls(
            id=header_fields[0],
            qr=qr,
            opcode=opcode,
            aa=aa,
            tc=tc,
            rd=rd,
            ra=ra,
            rcode=rcode,
            qdcount=header_fields[3],
            ancount=header_fields[4],
            nscount=header_fields[5],
            arcount=header_fields[6],
            questions=[],
            answers=[],
            authorities=[],
            additional=[],
        )

    def to_raw(self):
        raise NotImplementedError


@dataclass
class DnsQuestionSection: pass
