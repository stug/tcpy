import random
import socket
import struct
from dataclasses import dataclass

from udp import send_udp_datagram
from udp import listen_for_udp_datagrams
from util import get_ip
from util import human_readable_ip_from_int
from util import human_readable_ip_to_int


DNS_PORT = 53

DNS_TYPE_A = 0x0001
DNS_TYPE_CNAME = 0x0005
DNS_TYPE_PTR = 0x000c
DNS_CLASS_IN = 0x0001  # internet addresses


@dataclass
class DnsPacket:
    HEADER_FORMAT = '!HBBHHHH'

    id: int = 0  # TODO: autogenerate
    qr: int = 0  # question
    opcode: int = 0  # standard query
    aa: bool = False  # authoritative answer
    tc: bool = False  # truncated
    rd: bool = True  # recursion desired
    ra: bool = False  # recursion available
    rcode: int = 0
    
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    questions: list = None
    answers: list = None
    authorities: list = None
    additional: list = None

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

    def __post_init__(self):
        if self.id == 0:
            self.id = random.getrandbits(16)

        self.qdcount = len(self.questions or [])
        self.ancount = len(self.answers or [])
        self.nscount = len(self.authorities or [])
        self.arcount = len(self.additional or [])

    def to_raw(self):
        assert (self.ancount + self.nscount + self.arcount) == 0, \
            'Cannot serialize a dns packet with answer, authorities, or ' \
            'additional sections'

        qr_opcode_aa_tc_rd = self.qr << 7
        qr_opcode_aa_tc_rd += (self.opcode << 3)
        qr_opcode_aa_tc_rd += (int(self.aa) << 2)
        qr_opcode_aa_tc_rd += (int(self.tc) << 1)
        qr_opcode_aa_tc_rd += int(self.rd)

        ra_rcode = (int(self.ra) << 7) + self.rcode

        raw_packet = struct.pack(
            self.HEADER_FORMAT,
            self.id,
            qr_opcode_aa_tc_rd,
            ra_rcode,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )
        for question in self.questions:
            raw_packet += question.to_raw()

        return raw_packet



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
                labels.append(label)
                index += label_length
            else:
                break

    return b'.'.join(labels), index


def create_dns_name(name):
    dns_name = b''
    labels = name.split('.')
    for label in labels:
        length = len(label)
        dns_name += length.to_bytes(1, byteorder='big', signed=False)
        dns_name += label.encode('utf-8')

    return dns_name + b'\x00'


@dataclass
class DnsQuestionSection:
    record_name: bytes
    record_type: int
    record_class: int

    @classmethod
    def from_raw(cls, raw_dns_packet, index):
        # because DNS packets only specify a domain name once and thereafter
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
        # this is simplistic and does not implement that label/pointer business
        # since we only expect to do a single lookup at a time
        name = create_dns_name(self.record_name)
        type_and_class = struct.pack('!HH', self.record_type, self.record_class)
        return name + type_and_class


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


def get_nameserver_ip():
    # This is a little bonkers because of systemd, which sets up /etc/resolv.conf
    # to only list a 127.0.0.53 nameserver, which is just served by a local
    # cache of DNS results. The real nameserver is available by running
    # `resolvectl status`, and it appears systemd also stores it in
    # /run/systemd/resolve/resolv.conf for programs to read, but I am not sure
    # how generalizable this is :-/
    with open('/run/systemd/resolve/resolv.conf') as f:
        for line in f:
            if line.startswith('nameserver '):
                human_ip = line[len('nameserver '):]
                return human_readable_ip_to_int(human_ip)

    raise Exception('Could not determine nameserver!')


def perform_dns_lookup(sock, name, record_type):
    nameserver_ip = get_nameserver_ip()
    question = DnsQuestionSection(
        record_name=name,
        record_type=record_type,
        record_class=DNS_CLASS_IN,
    )
    dns_packet = DnsPacket(questions=[question])

    interface = sock.getsockname()[0]
    source_ip = get_ip(interface)

    # this socket is just so that we can get an ephemeral port to use as a
    # source port
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) as udp_sock:
        udp_sock.bind((human_readable_ip_from_int(source_ip), 0))
        source_port = udp_sock.getsockname()[1]
        send_udp_datagram(
            sock=sock,
            source_port=source_port,
            destination_ip=nameserver_ip,
            destination_port=DNS_PORT,
            payload=dns_packet.to_raw(),
        )
        for udp_datagram in listen_for_udp_datagrams(
            sock=sock,
            source_ip=nameserver_ip,
            source_port=DNS_PORT,
            destination_port=source_port,
        ):
            dns_packet = DnsPacket.from_raw(udp_datagram.payload)

            assert dns_packet.qr == 1  # response
            assert not dns_packet.tc, 'Cannot handle truncated DNS responses'
            assert dns_packet.ra, \
                'Can only handle responses from nameservers supporting recursion'
            assert dns_packet.rcode in (0, 3), \
                f'Received error in DNS response rcode field: {dns_packet.rcode}'

            return dns_packet


def get_ip_for_name(sock, name):
    response = perform_dns_lookup(sock, name, DNS_TYPE_A)
    for answer in response.answers:
        if answer.record_type == DNS_TYPE_A:
            return int.from_bytes(answer.rdata, byteorder='big', signed=False)
    return None


def human_readable_ip_to_arpa_domain(ip):
    octets = ip.split('.')
    reversed_octet_string = '.'.join(reversed(octets))
    return f'{reversed_octet_string}.in-addr.arpa'
