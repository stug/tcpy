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

        ancount = header_fields[4]
        answers, index = parse_resource_records(raw_packet, ancount, index)

        nscount = header_fields[5]
        authorities, index = parse_resource_records(raw_packet, nscount, index)

        arcount = header_fields[6]
        additional, index = parse_resource_records(raw_packet, arcount, index)

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
            ancount=ancount,
            nscount=nscount,
            arcount=arcount,
            questions=questions,
            answers=answers,
            authorities=authorities,
            additional=additional,
        )

    def to_raw(self):
        raise NotImplementedError


def parse_resource_records(raw_dns_packet, count, index):
    records = []
    for _ in range(count):
        resource_record, index = DnsResourceRecord.from_raw(raw_dns_packet, index)
        records.append(resource_record)
    return records, index


def parse_dns_name(raw_dns_packet, index):
    # A tricky thing here is that pointers are two-octet sequences whose first
    # two bits are 1s, whereas other labels are identified by a one-octet length
    # specifier starting with two 0's. So how many octets we look at depends on
    # the first two bits we see.
    # Also, the two conditions that end parsing are 1) hitting a null byte,
    # which signifies the end of a sequence of labels, and 2) hitting a pointer,
    # which redirects us to another set of labels elsewhere, which we follow
    # to their end -- we actually recurse in this case.
    labels = []
    while True:
        # weirdly, even though raw_dns_packet has type bytes, accessing a single
        # octet returns an int
        is_pointer = (raw_dns_packet[index] >> 6) == 0b11
        if is_pointer:
            [pointer_index] = struct.unpack('!H', raw_dns_packet[index: index+2])
            pointer_index = pointer_index & 0x3FFF  # zero out the two bit pointer marker
            index += 2
            label, _ = parse_dns_name(raw_dns_packet, pointer_index)
            labels.append(label)
            break
        else:
            label_length = raw_dns_packet[index]
            index += 1
            if label_length > 0:
                label = raw_dns_packet[index: index + label_length]
                index += label_length
            else:
                break

    return b'.'.join(labels), index


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

    def to_raw(self):
        raise NotImplementedError


@dataclass
class DnsResourceRecord:
    record_name: bytes
    record_type: int
    record_class: int
    ttl: int
    rdlength: int
    rdata: bytes

    @classmethod
    def from_raw(cls, raw_dns_packet, index):
        record_name, index = parse_dns_name(raw_dns_packet, index)
        record_type, record_class, ttl, rdlength = struct.unpack(
            '!HHLH',
            raw_dns_packet[index: index+10]
        )
        index += 10
        rdata = raw_dns_packet[index: index + rdlength]
        index += rdlength
        resource_record = cls(
            record_name=record_name,
            record_type=record_type,
            record_class=record_class,
            ttl=ttl,
            rdlength=rdlength,
            rdata=rdata
        )
        return resource_record, index
