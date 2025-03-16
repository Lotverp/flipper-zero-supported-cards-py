#!/usr/bin/env python3
import sys
from math import ceil

# --- TLV constants ---
NdefTlvPadding      = 0x00
NdefTlvLockControl  = 0x01
NdefTlvMemoryControl= 0x02
NdefTlvNdefMessage  = 0x03
NdefTlvProprietary  = 0xFD
NdefTlvTerminator   = 0xFE

# --- TNF (Type Name Format) constants ---
NdefTnfEmpty         = 0x00
NdefTnfWellKnownType = 0x01
NdefTnfMediaType     = 0x02
NdefTnfAbsoluteUri   = 0x03
NdefTnfExternalType  = 0x04
NdefTnfUnknown       = 0x05
NdefTnfUnchanged     = 0x06
NdefTnfReserved      = 0x07

# URI prefix mapping (only a subset)
ndef_uri_prepends = {
    0x00: "",
    0x01: "http://www.",
    0x02: "https://www.",
    0x03: "http://",
    0x04: "https://",
    0x05: "tel:",
    0x06: "mailto:",
    # ... add others as needed
}

# --- NDEF Parser Class ---
class Ndef:
    def __init__(self, data: bytes):
        self.data = data  # Assumed contiguous memory holding NDEF TLV data
        self.output = ""
    
    def get(self, pos: int, length: int) -> bytes:
        if pos + length > len(self.data):
            raise ValueError("Out-of-bounds access in NDEF data")
        return self.data[pos: pos+length]
    
    def dump(self, prefix: str, pos: int, length: int, force_hex: bool=False) -> None:
        chunk = self.get(pos, length)
        # If not forced to hex, check if all characters are printable
        if not force_hex and all(32 <= b < 127 or b in (9,10,13) for b in chunk):
            self.output += (prefix + ": " if prefix else "") + chunk.decode('utf-8', errors='replace') + "\n"
        else:
            hex_str = " ".join(f"{b:02X}" for b in chunk)
            self.output += (prefix + ": " if prefix else "") + hex_str + "\n"
    
    def print_value(self, prefix: str, buf: bytes, force_hex: bool=False) -> None:
        if not force_hex and all(32 <= b < 127 or b in (9,10,13) for b in buf):
            self.output += f"{prefix}: {buf.decode('utf-8', errors='replace')}\n"
        else:
            hex_str = " ".join(f"{b:02X}" for b in buf)
            self.output += f"{prefix}: {hex_str}\n"

# --- Parsing functions for specific record types ---
def parse_ndef_uri(ndef: Ndef, pos: int, length: int) -> None:
    # The first byte is the URI identifier code
    prepend_type = ndef.get(pos, 1)[0]
    pos += 1
    length -= 1
    prepend = ndef_uri_prepends.get(prepend_type, "")
    uri_payload = ndef.get(pos, length).decode('utf-8', errors='replace')
    ndef.output += "URI\n" + prepend + uri_payload + "\n"

def parse_ndef_text(ndef: Ndef, pos: int, length: int) -> None:
    # First byte: language code length
    lang_len = ndef.get(pos, 1)[0]
    pos += 1
    length -= 1
    # Skip language code
    language = ndef.get(pos, lang_len).decode('utf-8', errors='replace')
    pos += lang_len
    length -= lang_len
    text_payload = ndef.get(pos, length).decode('utf-8', errors='replace')
    ndef.output += "Text\n" + text_payload + "\n"

def parse_ndef_bt(ndef: Ndef, pos: int, length: int) -> None:
    # Skip first 2 bytes, then output remaining as hex
    bt_mac = ndef.get(pos+2, length-2)
    hex_str = " ".join(f"{b:02X}" for b in bt_mac)
    ndef.output += "BT MAC\n" + hex_str + "\n"

def parse_ndef_vcard(ndef: Ndef, pos: int, length: int) -> None:
    # Simply output payload as text
    text = ndef.get(pos, length).decode('utf-8', errors='replace')
    ndef.output += "Contact\n" + text + "\n"

def parse_ndef_wifi(ndef: Ndef, pos: int, length: int) -> None:
    # For simplicity, output WiFi payload as hex
    hex_str = " ".join(f"{b:02X}" for b in ndef.get(pos, length))
    ndef.output += "WiFi\n" + hex_str + "\n"

# --- Record and Message Parsing ---
def parse_ndef_record(ndef: Ndef, pos: int, message_num: int) -> int:
    # Read flags (1 byte)
    flags = ndef.get(pos, 1)[0]
    pos += 1
    mb = (flags >> 7) & 0x1
    me = (flags >> 6) & 0x1
    cf = (flags >> 5) & 0x1
    sr = (flags >> 4) & 0x1
    il = (flags >> 3) & 0x1
    tnf = flags & 0x07

    # For our parser, we don't support chunking
    if cf:
        raise ValueError("Chunked records not supported")

    # Type Length (1 byte)
    type_len = ndef.get(pos, 1)[0]
    pos += 1

    # Payload length: 1 byte if sr is set, else 4 bytes (big-endian)
    if sr:
        payload_len = ndef.get(pos, 1)[0]
        pos += 1
    else:
        payload_len = int.from_bytes(ndef.get(pos, 4), byteorder='big')
        pos += 4

    # ID length if present
    id_len = 0
    if il:
        id_len = ndef.get(pos, 1)[0]
        pos += 1

    # Get Type field
    type_field = ndef.get(pos, type_len)
    pos += type_len
    # Skip ID field if present
    pos += id_len

    # Dispatch based on TNF and type
    if tnf == NdefTnfWellKnownType:
        if type_field == b"U":
            parse_ndef_uri(ndef, pos, payload_len)
        elif type_field == b"T":
            parse_ndef_text(ndef, pos, payload_len)
        else:
            ndef.dump("Unknown Well-known", pos, payload_len)
    elif tnf == NdefTnfMediaType:
        if type_field == b"application/vnd.bluetooth.ep.oob":
            parse_ndef_bt(ndef, pos, payload_len)
        elif type_field == b"text/vcard":
            parse_ndef_vcard(ndef, pos, payload_len)
        elif type_field == b"application/vnd.wfa.wsc":
            parse_ndef_wifi(ndef, pos, payload_len)
        else:
            ndef.dump("Unknown Media", pos, payload_len)
    else:
        ndef.dump("Unsupported TNF", pos, payload_len)
    
    pos += payload_len
    return pos

def parse_ndef_message(ndef: Ndef, pos: int, length: int, message_num: int) -> int:
    end = pos + length
    while pos < end:
        pos = parse_ndef_record(ndef, pos, message_num)
    return pos

def parse_ndef_tlv(ndef: Ndef, pos: int, length: int, already_parsed: int) -> int:
    end = pos + length
    message_count = already_parsed
    while pos < end:
        tlv_type = ndef.get(pos, 1)[0]
        pos += 1
        if tlv_type == NdefTlvPadding:
            continue
        elif tlv_type == NdefTlvTerminator:
            return message_count
        elif tlv_type in (NdefTlvLockControl, NdefTlvMemoryControl, NdefTlvProprietary, NdefTlvNdefMessage):
            # Determine length field
            len_type = ndef.get(pos, 1)[0]
            pos += 1
            if len_type < 0xFF:
                tlv_len = len_type
            else:
                tlv_len = int.from_bytes(ndef.get(pos, 2), byteorder='big')
                pos += 2
            if tlv_type != NdefTlvNdefMessage:
                pos += tlv_len
            else:
                message_count += 1
                pos = parse_ndef_message(ndef, pos, tlv_len, message_count)
        else:
            return 0
    return message_count

def parse_ndef(data: bytes) -> str:
    ndef = Ndef(data)
    try:
        message_count = parse_ndef_tlv(ndef, 0, len(data), 0)
        if message_count == 0:
            return "No NDEF messages found."
        return ndef.output.strip()
    except Exception as e:
        return f"Error during parsing: {e}"

def main():
    if len(sys.argv) != 2:
        print("Usage: python ndef.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            data = f.read()
        result = parse_ndef(data)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
