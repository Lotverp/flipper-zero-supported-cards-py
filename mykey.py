#!/usr/bin/env python3
import sys
import struct

# Costanti di riferimento (in C, definite come macros)
blankBlock18 = 0x480FCD8F
blankBlock19 = 0x070082C0
EXPECTED_TYPE = ("04k", "X4k")
SYSTEM_OTP_EXPECTED = 0xFEFFFFFF

# Funzione per fare byte-swap a 32 bit (equivalente a __bswap32)
def bs_swap32(x: int) -> int:
    return int.from_bytes(x.to_bytes(4, byteorder='little'), byteorder='big')

# Funzioni "helper" per MyKey

def mykey_is_blank(data: dict) -> bool:
    return data["blocks"][0x18] == blankBlock18 and data["blocks"][0x19] == blankBlock19

def mykey_has_lockid(data: dict) -> bool:
    # Prende il blocco 5, shift 24 bit a destra e lo confronta con 0x7F
    return (data["blocks"][5] >> 24) == 0x7F

def check_invalid_low_nibble(value: int) -> bool:
    return (value & 0xF) >= 0xA

def mykey_get_production_date(data: dict):
    # Estrae il blocco 8 (date_block)
    date_block = data["blocks"][8]
    year = (date_block >> 16) & 0xFF
    month = (date_block >> 8) & 0xFF
    day = date_block & 0xFF
    if day > 0x31 or month > 0x12 or day == 0 or month == 0 or year == 0:
        return None
    # Controlla se le cifre decimali sono valide (le cifre A-F sono invalide)
    if (check_invalid_low_nibble(day) or check_invalid_low_nibble(month) or
       check_invalid_low_nibble(year) or check_invalid_low_nibble(year >> 4)):
        return None
    return (year + 0x2000, month, day)

# Funzione per caricare il dump MyKey da un file
# Il file formato è:
#   • 1 byte: tipo (0 => "04k", 1 => "X4k")
#   • 4 byte: system_otp_block (big-endian)
#   • Il resto: blocchi, ciascuno di 4 byte (big-endian)
def load_mykey_data(filename: str) -> dict:
    with open(filename, "rb") as f:
        raw = f.read()
    if len(raw) < 5:
        raise ValueError("File troppo corto")
    type_byte = raw[0]
    card_type = "04k" if type_byte == 0 else "X4k"
    system_otp_block = int.from_bytes(raw[1:5], byteorder='big')
    blocks = []
    # I blocchi iniziano dal byte 5
    for i in range(5, len(raw), 4):
        block = int.from_bytes(raw[i:i+4], byteorder='big')
        blocks.append(block)
    return {"type": card_type, "system_otp_block": system_otp_block, "blocks": blocks}

def mykey_parse(data: dict) -> str:
    # Controlla tipo
    if data["type"] not in EXPECTED_TYPE:
        return "bad type"
    # Controlla OTP blocks: i primi 5 blocchi devono essere 0xFFFFFFFF
    for i in range(5):
        if data["blocks"][i] != 0xFFFFFFFF:
            return f"bad otp block {i}"
    prod_date = mykey_get_production_date(data)
    if prod_date is None:
        return "bad mfg date"
    mfg_year, mfg_month, mfg_day = prod_date
    if data["system_otp_block"] != SYSTEM_OTP_EXPECTED:
        return "bad sys otp block"

    output = "\e#MyKey\n"

    # Se il blocco 6 è 0, la carta è bricked
    if data["blocks"][6] == 0:
        output += "\e#Bricked!\nBlock 6 is 0!"
        return output

    is_blank = mykey_is_blank(data)
    serial = bs_swap32(data["blocks"][7])
    output += "Serial#: %08X\n" % serial
    # Stampa la data di produzione: giorno e mese in esadecimale, anno in decimale
    output += "Prod. date: %02X/%02X/%04d\n" % (mfg_day, mfg_month, mfg_year)
    output += "Blank: %s\n" % ("yes" if is_blank else "no")
    output += "LockID: %s" % ("maybe" if mykey_has_lockid(data) else "no")

    if not is_blank:
        op_count = bs_swap32(data["blocks"][0x12] & 0xFFFFFF00)
        output += "\nOp. count: %d\n" % op_count
        block3C = data["blocks"][0x3C]
        if block3C == 0xFFFFFFFF:
            output += "No history available!"
        else:
            # block3C XOR with block 7
            block3C ^= data["blocks"][0x07]
            startingOffset = ((block3C & 0x30000000) >> 28) | ((block3C & 0x00100000) >> 18)
            if startingOffset >= 8:
                return "Error: startingOffset >= 8"
            output += "Op. history (newest first):"
            for txnOffset in range(8, 0, -1):
                index = 0x34 + ((startingOffset + txnOffset) % 8)
                txnBlock = bs_swap32(data["blocks"][index])
                if txnBlock == 0xFFFFFFFF:
                    break
                day = txnBlock >> 27
                month = (txnBlock >> 23) & 0xF
                year = 2000 + ((txnBlock >> 16) & 0x7F)
                credit = txnBlock & 0xFFFF
                if txnOffset == 8:
                    output = "Current credit: %d.%02d euros\n" % (credit // 100, credit % 100) + output
                output += "\n    %02d/%02d/%04d %d.%02d" % (day, month, year, credit // 100, credit % 100)
    return output

def main():
    if len(sys.argv) != 2:
        print("Usage: python mykey.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        data = load_mykey_data(dump_file)
        result = mykey_parse(data)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
