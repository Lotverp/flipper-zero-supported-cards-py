#!/usr/bin/env python3
import sys
import struct

# Costanti Saflok
MAGIC_TABLE_SIZE = 192
KEY_LENGTH = 6
UID_LENGTH = 4
CHECK_SECTOR = 1
BASIC_ACCESS_BYTE_NUM = 17
SAFLOK_YEAR_OFFSET = 1980

# Definizione di un "key pair" per i settori (per una 1K)
# I valori sono espressi in esadecimale (64 bit)
saflok_1k_keys = [
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 000
    {"a": 0x2a2c13cc242a, "b": 0xffffffffffff},  # 001
    {"a": 0xffffffffffff, "b": 0xffffffffffff},  # 002
    {"a": 0xffffffffffff, "b": 0xffffffffffff},  # 003
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 004
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 005
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 006
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 007
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 008
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 009
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 010
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 011
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 012
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 013
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 014
    {"a": 0x000000000000, "b": 0xffffffffffff},  # 015
]

# Livelli di chiave (lookup table)
key_levels = {
    1: "Guest Key",
    2: "Connectors",
    3: "Suite",
    4: "Limited Use",
    5: "Failsafe",
    6: "Inhibit",
    7: "Pool/Meeting Master",
    8: "Housekeeping",
    9: "Floor Key",
    10: "Section Key",
    11: "Rooms Master",
    12: "Grand Master",
    13: "Emergency",
    14: "Electronic Lockout",
    15: "Secondary Programming Key (SPK)",
    16: "Primary Programming Key (PPK)"
}

weekdays = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

# --- Funzioni KDF e decryption ---

def generate_saflok_key(uid: bytes) -> bytes:
    """
    Genera la chiave Saflok (6 byte) in base all'UID.
    Basato sulla KDF reverse-engineered da Jaden Wu.
    """
    # Tabella "magic"
    magic_table = bytes([
        0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xF0, 0x57, 0xB3, 0x9E, 0xE3, 0xD8, 0x00, 0x00, 0xAA,
        0x00, 0x00, 0x00, 0x96, 0x9D, 0x95, 0x4A, 0xC1, 0x57, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00,
        0x8F, 0x43, 0x58, 0x0D, 0x2C, 0x9D, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xFF, 0xCC, 0xE0,
        0x05, 0x0C, 0x43, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x34, 0x1B, 0x15, 0xA6, 0x90, 0xCC,
        0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x89, 0x58, 0x56, 0x12, 0xE7, 0x1B, 0x00, 0x00, 0xAA,
        0x00, 0x00, 0x00, 0xBB, 0x74, 0xB0, 0x95, 0x36, 0x58, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00,
        0xFB, 0x97, 0xF8, 0x4B, 0x5B, 0x74, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xC9, 0xD1, 0x88,
        0x35, 0x9F, 0x92, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x8F, 0x92, 0xE9, 0x7F, 0x58, 0x97,
        0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x16, 0x6C, 0xA2, 0xB0, 0x9F, 0xD1, 0x00, 0x00, 0xAA,
        0x00, 0x00, 0x00, 0x27, 0xDD, 0x93, 0x10, 0x1C, 0x6C, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00,
        0xDA, 0x3E, 0x3F, 0xD6, 0x49, 0xDD, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x58, 0xDD, 0xED,
        0x07, 0x8E, 0x3E, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x5C, 0xD0, 0x05, 0xCF, 0xD9, 0x07,
        0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x11, 0x8D, 0xD0, 0x01, 0x87, 0xD0
    ])
    # Assumiamo che magic_table abbia esattamente 192 byte.
    magic_byte = ((uid[3] >> 4) + (uid[2] >> 4) + (uid[0] & 0x0F)) & 0xFF
    magickal_index = ((magic_byte & 0x0F) * 12) + 11
    # Inizializza temp_key come [magic_byte, uid[0], uid[1], uid[2], uid[3], magic_byte]
    temp_key = bytearray([magic_byte, uid[0], uid[1], uid[2], uid[3], magic_byte])
    carry_sum = 0
    # Itera da KEY_LENGTH-1 a 0
    for i in reversed(range(KEY_LENGTH)):
        keysum = temp_key[i] + magic_table[magickal_index] + carry_sum
        temp_key[i] = keysum & 0xFF
        carry_sum = keysum >> 8
        magickal_index -= 1
    return bytes(temp_key)

def CalculateCheckSum(data: bytes) -> int:
    # Calcola la somma dei primi BASIC_ACCESS_BYTE_NUM-1 byte e restituisce 255 - (somma mod 256)
    total = sum(data[:-1])
    return (255 - (total & 0xFF)) & 0xFF

def DecryptCard(strCard: bytes) -> bytes:
    """
    Decripta il Basic Access (17 byte) della Saflok card.
    """
    if len(strCard) != BASIC_ACCESS_BYTE_NUM:
        raise ValueError("Invalid Basic Access length")
    decoded = bytearray(BASIC_ACCESS_BYTE_NUM)
    # Prima fase: per ogni byte, applica c_aDecode e sottrai (i+1)
    # c_aDecode è una lookup table di 256 byte (definita sotto)
    c_aDecode = [
        0xEA, 0x0D, 0xD9, 0x74, 0x4E, 0x28, 0xFD, 0xBA, 0x7B, 0x98, 0x87, 0x78, 0xDD, 0x8D, 0xB5,
        0x1A, 0x0E, 0x30, 0xF3, 0x2F, 0x6A, 0x3B, 0xAC, 0x09, 0xB9, 0x20, 0x6E, 0x5B, 0x2B, 0xB6,
        0x21, 0xAA, 0x17, 0x44, 0x5A, 0x54, 0x57, 0xBE, 0x0A, 0x52, 0x67, 0xC9, 0x50, 0x35, 0xF5,
        0x41, 0xA0, 0x94, 0x60, 0xFE, 0x24, 0xA2, 0x36, 0xEF, 0x1E, 0x6B, 0xF7, 0x9C, 0x69, 0xDA,
        0x9B, 0x6F, 0xAD, 0xD8, 0xFB, 0x97, 0x62, 0x5F, 0x1F, 0x38, 0xC2, 0xD7, 0x71, 0x31, 0xF0,
        0x13, 0xEE, 0x0F, 0xA3, 0xA7, 0x1C, 0xD5, 0x11, 0x4C, 0x45, 0x2C, 0x04, 0xDB, 0xA6, 0x2E,
        0xF8, 0x64, 0x9A, 0xB8, 0x53, 0x66, 0xDC, 0x7A, 0x5D, 0x03, 0x07, 0x80, 0x37, 0xFF, 0xFC,
        0x06, 0xBC, 0x26, 0xC0, 0x95, 0x4A, 0xF1, 0x51, 0x2D, 0x22, 0x18, 0x01, 0x79, 0x5E, 0x76,
        0x1D, 0x7F, 0x14, 0xE3, 0x9E, 0x8A, 0xBB, 0x34, 0xBF, 0xF4, 0xAB, 0x48, 0x63, 0x55, 0x3E,
        0x56, 0x8C, 0xD1, 0x12, 0xED, 0xC3, 0x49, 0x8E, 0x92, 0x9D, 0xCA, 0xB1, 0xE5, 0xCE, 0x4D,
        0x3F, 0xFA, 0x73, 0x05, 0xE0, 0x4B, 0x93, 0xB2, 0xCB, 0x08, 0xE1, 0x96, 0x19, 0x3D, 0x83,
        0x39, 0x75, 0xEC, 0xD6, 0x3C, 0xD0, 0x70, 0x81, 0x16, 0x29, 0x15, 0x6C, 0xC7, 0xE7, 0xE2,
        0xF6, 0xB7, 0xE8, 0x25, 0x6D, 0x3A, 0xE6, 0xC8, 0x99, 0x46, 0xB0, 0x85, 0x02, 0x61, 0x1B,
        0x8B, 0xB3, 0x9F, 0x0B, 0x2A, 0xA8, 0x77, 0x10, 0xC1, 0x88, 0xCC, 0xA4, 0xDE, 0x43, 0x58,
        0x23, 0xB4, 0xA1, 0xA5, 0x5C, 0xAE, 0xA9, 0x7E, 0x42, 0x40, 0x90, 0xD2, 0xE9, 0x84, 0xCF,
        0xE4, 0xEB, 0x47, 0x4F, 0x82, 0xD4, 0xC5, 0x8F, 0xCD, 0xD3, 0x86, 0x00, 0x59, 0xDF, 0xF2,
        0x0C, 0x7C, 0xC6, 0xBD, 0xF9, 0x7D, 0xC4, 0x91, 0x27, 0x89, 0x32, 0x72, 0x33, 0x65, 0x68,
        0xAF
    ]
    # Calcola magic_byte: somma dei nibble superiori di uid[3] e uid[2], più il nibble inferiore di uid[0]
    magic_byte = (((uid[3] >> 4) + (uid[2] >> 4) + (uid[0] & 0x0F)) & 0xFF)
    magickal_index = ((magic_byte & 0x0F) * 12) + 11

    temp_key = bytearray([magic_byte, uid[0], uid[1], uid[2], uid[3], magic_byte])
    carry_sum = 0
    for i in reversed(range(KEY_LENGTH)):
        keysum = temp_key[i] + magic_table[magickal_index] + carry_sum
        temp_key[i] = keysum & 0xFF
        carry_sum = keysum >> 8
        magickal_index -= 1
    return bytes(temp_key)

def mykey_parse(card_data: bytes) -> str:
    # Assumiamo che il dump della carta sia un array di 32-bit interi (big-endian)
    if len(card_data) < 5 * 4:
        return "Error: dump too short."
    
    # I primi 5 blocchi devono essere 0xFFFFFFFF
    for i in range(5):
        if int.from_bytes(card_data[i*4:(i+1)*4], 'big') != 0xFFFFFFFF:
            return f"Bad OTP block {i}"
    
    # Blocco 8: production date
    date_block = int.from_bytes(card_data[8*4:(8+1)*4], 'big')
    year = (date_block >> 16) & 0xFF
    month = (date_block >> 8) & 0xFF
    day = date_block & 0xFF
    if day > 0x31 or month > 0x12 or day == 0 or month == 0 or year == 0:
        return "Bad mfg date"
    if any((x & 0xF) >= 0xA for x in [day, month, year, year >> 4]):
        return "Bad mfg date"
    mfg_year = year + 0x2000

    # system_otp_block (blocco 1)
    sys_otp = int.from_bytes(card_data[1*4:2*4], 'big')
    if sys_otp != 0xFEFFFFFF:
        return "Bad sys otp block"

    output = "Opal Card\n"
    # Se il blocco 6 è 0, la carta è bricked
    block6 = int.from_bytes(card_data[6*4:(6+1)*4], 'big')
    if block6 == 0:
        output += "Bricked! Block 6 is 0!\n"
        return output

    # Serial number: dal blocco 7 (byte-swapped)
    block7 = int.from_bytes(card_data[7*4:(7+1)*4], 'big')
    serial = int.from_bytes(block7.to_bytes(4, 'big')[::-1], 'big')
    output += f"Serial#: {serial:08X}\n"
    output += f"Prod. date: {day:02X}/{month:02X}/{mfg_year}\n"

    # Blank: controlla blocchi 0x18 e 0x19
    block18 = int.from_bytes(card_data[0x18*4:(0x18+1)*4], 'big')
    block19 = int.from_bytes(card_data[0x19*4:(0x19+1)*4], 'big')
    blank = (block18 == 0x480FCD8F and block19 == 0x070082C0)
    output += f"Blank: {'yes' if blank else 'no'}\n"
    # LockID: dal blocco 5
    lockid = (int.from_bytes(card_data[5*4:(5+1)*4], 'big') >> 24) == 0x7F
    output += f"LockID: {'maybe' if lockid else 'no'}\n"
    
    if not blank:
        op_count = int.from_bytes(card_data[0x12*4:(0x12+1)*4], 'big') & 0xFFFFFF00
        op_count = int.from_bytes(op_count.to_bytes(4, 'big')[::-1], 'big')
        output += f"Op. count: {op_count}\n"

        block3C = int.from_bytes(card_data[0x3C*4:(0x3C+1)*4], 'big')
        if block3C == 0xFFFFFFFF:
            output += "No history available!"
        else:
            block7_val = int.from_bytes(card_data[7*4:(7+1)*4], 'big')
            block3C ^= block7_val
            startingOffset = ((block3C & 0x30000000) >> 28) | ((block3C & 0x00100000) >> 18)
            if startingOffset >= 8:
                return "Error: startingOffset >= 8"
            output += "Op. history (newest first):"
            for txnOffset in range(8, 0, -1):
                index = 0x34 + ((startingOffset + txnOffset) % 8)
                txnBlock = int.from_bytes(card_data[index*4:(index+1)*4], 'big')
                txnBlock = int.from_bytes(txnBlock.to_bytes(4, 'big')[::-1], 'big')
                if txnBlock == 0xFFFFFFFF:
                    break
                day_val = txnBlock >> 27
                month_val = (txnBlock >> 23) & 0xF
                year_val = 2000 + ((txnBlock >> 16) & 0x7F)
                credit = txnBlock & 0xFFFF
                if txnOffset == 8:
                    output = f"Current credit: {credit // 100}.{credit % 100:02d} euros\n" + output
                output += f"\n    {day_val:02d}/{month_val:02d}/{year_val} {credit // 100}.{credit % 100:02d}"
    return output

def main():
    if len(sys.argv) != 2:
        print("Usage: python saflok.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        result = saflok_parse(card_data)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
