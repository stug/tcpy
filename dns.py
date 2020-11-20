import struct
from dataclasses import dataclass


DNS_TYPE_A = 0x0001
DNS_TYPE_CNAME = 0x0005
DNS_CLASS_IN = 0x0001  # internet addresses


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

        index = struct.calcsize(cls.HEADER_FORMAT)

        qdcount = header_fields[3]
        questions = []
        for _ in range(qdcount):
            question, index = DnsQuestionSection.from_raw(raw_packet, index)
            questions.append(question)

        return cls(
            id=header_fields[0],
            qr=qr,
            opcode=opcode,
            aa=aa,
            tc=tc,
            rd=rd,
            ra=ra,
            rcode=rcode,
            qdcount=qdcount,
            ancount=header_fields[4],
            nscount=header_fields[5],
            arcount=header_fields[6],
            questions=questions,
            answers=[],
            authorities=[],
            additional=[],
        )

    def to_raw(self):
        raise NotImplementedError


def parse_dns_name(raw_dns_packet, index):
    labels = []
    while True:
        label, index = parse_dns_label(raw_dns_packet, index)
        if label is None:
            break
        labels.append(label)

    return b'.'.join(labels), index


def parse_dns_label(raw_dns_packet, index):
    # even though raw_dns_packet has type bytes, accessing a single
    # octet returns an int, weirdly.
    label_length_or_pointer = raw_dns_packet[index]
    index += 1
    is_pointer = (label_length_or_pointer >> 6) == 0b11
    if is_pointer:
        pointer_index = label_length_or_pointer & 0x3F
        label, _ = parse_dns_label(raw_dns_packet, pointer_index)
    elif label_length_or_pointer > 0:
        label = raw_dns_packet[index: index + label_length_or_pointer]
        index = index + label_length_or_pointer
    else:
        label = None

    return label, index


@dataclass
class DnsQuestionSection:

    record_name: bytes
    record_type: int
    record_class: int

    @classmethod
    def from_raw(cls, raw_dns_packet, index):
        # because DNS packet only specify a domain name once and thereafter
        # refer to it via a pointer to the original name, we need access to the
        # entire DNS packet in case we need to look up a name defined elsewhere
        record_name, index = parse_dns_name(raw_dns_packet, index)
        record_type, record_class = struct.unpack('!HH', raw_dns_packet[index: index+4])

        index += 4
        question_section = cls(
            record_name=record_name,
            record_type=record_type,
            record_class=record_class
        )
        return question_section, index
