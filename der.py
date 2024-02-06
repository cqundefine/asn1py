from enum import IntEnum
import datetime
import io
import base64
import asn1

class TagClass(IntEnum):
    Universal = 0b00
    Application = 0b01
    ContextSpecific = 0b10
    Private = 0b11

class Tag(IntEnum):
    BOOLEAN = 0x1
    INTEGER = 0x2
    BIT_STRING = 0x3
    OCTET_STRING = 0x4
    NULL = 0x5
    OBJECT_IDENTIFIER = 0x6
    SEQUENCE = 0x10
    SET = 0x11
    PRINTABLE_STRING = 0x13
    UTC_TIME = 0x17

def _parse_u1(f): return int.from_bytes(f.read(1), "big")
def _parse_uN(f, N): return int.from_bytes(f.read(N), "big") 

def parse(f) -> asn1.Node:
    tag = _parse_u1(f)
    tag_class = (tag & 0xC0) >> 6
    constructed = bool((tag & 0x3F) >> 5)
    base_tag = tag & 0x1F

    length = _parse_u1(f)
    isLongForm = bool(length & 0x80)
    if isLongForm:
        byteCount = (length & ~0x80)
        length = _parse_uN(f, byteCount)
    
    bytes = f.read(length)
    
    if tag_class == TagClass.Universal:
        if base_tag == Tag.BOOLEAN:
            return asn1.Boolean(length, constructed, bool(bytes[0]))
        elif base_tag == Tag.INTEGER:
            return asn1.Integer(length, constructed, _parse_uN(io.BytesIO(bytes), length))
        elif base_tag == Tag.NULL:
            return asn1.Null(length, constructed)
        elif base_tag == Tag.OBJECT_IDENTIFIER:
            oid = []
            bytesIO = io.BytesIO(bytes)
            firstByte = _parse_u1(bytesIO)
            oid.append(firstByte // 40)
            oid.append(firstByte % 40)  
            while bytesIO.tell() < length:
                byte = _parse_u1(bytesIO)
                oid.append(byte & 0x7F)
                while byte & 0x80:
                    byte = _parse_u1(bytesIO)
                    oid[-1] = (oid[-1] << 7) | (byte & 0x7F)
            return asn1.ObjectIdentifier(length, constructed, oid)
        elif base_tag == Tag.SEQUENCE:
            sequence = []
            bytesIO = io.BytesIO(bytes)
            while bytesIO.tell() < length:
                sequence.append(parse(bytesIO))
            return asn1.Sequence(length, constructed, sequence)
        elif base_tag == Tag.SET:
            set = []
            bytesIO = io.BytesIO(bytes)
            while bytesIO.tell() < length:
                set.append(parse(bytesIO))
            return asn1.Set(length, constructed, set)
        elif base_tag == Tag.PRINTABLE_STRING:
            return asn1.PrintableString(length, constructed, bytes.decode("ascii"))
        elif base_tag == Tag.UTC_TIME:
            return asn1.UTCTime(length, constructed, datetime.datetime.strptime(bytes.decode("ascii"), "%y%m%d%H%M%SZ"))
        else:
            print(f"Tag {hex(tag)} (base: {base_tag}) not implemented")
            return asn1.Invalid(length, constructed)
    elif tag_class == TagClass.ContextSpecific:
        return asn1.ContextSpecific(length, constructed, base_tag, parse(io.BytesIO(bytes)))
    else:
        print(f"Tag class {tag_class} not implemented")
        return asn1.Invalid(length, constructed)

PEM_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_FOOTER = "-----END CERTIFICATE-----"

def parse_from_file(file_path: str) -> asn1.Node:
    with open(file_path, 'rb') as f:
        if f.read(len(PEM_HEADER)) == PEM_HEADER.encode("ascii"):
            bytes = b""
            while True:
                line = f.readline()
                if line == PEM_FOOTER.encode("ascii") + b"\n":
                    break
                else:
                    bytes += line.replace(b"\n", b"").replace(b"\r", b"")
            bytes = base64.b64decode(bytes)
            return parse(io.BytesIO(bytes))
        else:
            f.seek(0)
            return parse(f)
