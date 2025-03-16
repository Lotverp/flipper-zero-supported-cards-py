#!/usr/bin/env python3
import sys
import struct

UID_LEN = 4
MAX_BLOCKS = 64  # Numero massimo di blocchi
# Funzione per leggere un blocco (16 byte) dal dump
def get_block(card_data: bytes, block_num: int) -> bytes:
    start = block_num * 16
    return card_data[start:start+16]

# Funzione per leggere un intero da un blocco (big-endian)
def get_number_be(data: bytes, start: int, length: int) -> int:
    return int.from_bytes(data[start:start+length], byteorder='big')

# Funzione per ottenere un intero da un blocco (considerato come array di 4-byte, es. per estrarre un campo a partire da un offset)
def get_bits(data: bytes, bit_offset: int, bit_length: int) -> int:
    # Calcoliamo il byte di partenza
    byte_offset = bit_offset // 8
    # Leggiamo abbastanza byte
    num_bytes = (bit_offset % 8 + bit_length + 7) // 8
    chunk = int.from_bytes(data[byte_offset:byte_offset+num_bytes], byteorder='big')
    # Spostiamo per eliminare i bit iniziali in eccesso
    shift = (num_bytes * 8) - (bit_offset % 8 + bit_length)
    return (chunk >> shift) & ((1 << bit_length) - 1)

# Funzione per convertire un numero esadecimale in "numero decimale" interpretando ogni nibble come cifra decimale
def hex_num(hex_val: int) -> int:
    result = 0
    multiplier = 1
    # Processa nibble per nibble (fino a 8 nibble per 32-bit)
    while hex_val:
        nibble = hex_val & 0xF
        result += nibble * multiplier
        multiplier *= 10
        hex_val //= 16
    return result

# Algoritmo Luhn per calcolare il check digit
def calculate_luhn(number: int) -> int:
    payload = number // 10
    total_sum = 0
    position = 0
    while payload > 0:
        digit = payload % 10
        if position % 2 == 0:
            digit *= 2
        if digit > 9:
            digit = (digit // 10) + (digit % 10)
        total_sum += digit
        payload //= 10
        position += 1
    return (10 - (total_sum % 10)) % 10

# Configurazioni per Social Moscow: per 1K e 4K
class SocialMoscowCardConfig:
    def __init__(self, keys, data_sector):
        self.keys = keys
        self.data_sector = data_sector

# Chiavi per Social Moscow per 1K
social_moscow_1k_keys = [
    {"a": 0xa0a1a2a3a4a5, "b": 0x7de02a7f6025},
    {"a": 0x2735fc181807, "b": 0xbf23a53c1f63},
    {"a": 0x2aba9519f574, "b": 0xcb9a1f2d7368},
    {"a": 0x84fd7f7a12b6, "b": 0xc7c0adb3284f},
    {"a": 0x73068f118c13, "b": 0x2b7f3253fac5},
    {"a": 0x186d8c4b93f9, "b": 0x9f131d8c2057},
    {"a": 0x3a4bba8adaf0, "b": 0x67362d90f973},
    {"a": 0x8765b17968a2, "b": 0x6202a38f69e2},
    {"a": 0x40ead80721ce, "b": 0x100533b89331},
    {"a": 0x0db5e6523f7c, "b": 0x653a87594079},
    {"a": 0x51119dae5216, "b": 0xd8a274b2e026},
    {"a": 0x51119dae5216, "b": 0xd8a274b2e026},
    {"a": 0x51119dae5216, "b": 0xd8a274b2e026},
    {"a": 0x2aba9519f574, "b": 0xcb9a1f2d7368},
    {"a": 0x84fd7f7a12b6, "b": 0xc7c0adb3284f},
    {"a": 0xa0a1a2a3a4a5, "b": 0x7de02a7f6025}
]

# Chiavi per Social Moscow per 4K
social_moscow_4k_keys = [
    {"a": 0xa0a1a2a3a4a5, "b": 0x7de02a7f6025},
    {"a": 0x2735fc181807, "b": 0xbf23a53c1f63},
    {"a": 0x2aba9519f574, "b": 0xcb9a1f2d7368},
    {"a": 0x84fd7f7a12b6, "b": 0xc7c0adb3284f},
    {"a": 0x73068f118c13, "b": 0x2b7f3253fac5},
    {"a": 0x186d8c4b93f9, "b": 0x9f131d8c2057},
    {"a": 0x3a4bba8adaf0, "b": 0x67362d90f973},
    {"a": 0x8765b17968a2, "b": 0x6202a38f69e2},
    {"a": 0x40ead80721ce, "b": 0x100533b89331},
    {"a": 0x0db5e6523f7c, "b": 0x653a87594079},
    {"a": 0x51119dae5216, "b": 0xd8a274b2e026},
    {"a": 0x51119dae5216, "b": 0xd8a274b2e026},
    {"a": 0x51119dae5216, "b": 0xd8a274b2e026},
    {"a": 0xa0a1a2a3a4a5, "b": 0x7de02a7f6025},
    {"a": 0xa0a1a2a3a4a5, "b": 0x7de02a7f6025},
    {"a": 0xa0a1a2a3a4a5, "b": 0x7de02a7f6025}
]

def social_moscow_get_card_config(card_type: str) -> SocialMoscowCardConfig:
    # Se card_type è "1k", usa le chiavi 1K, altrimenti "4k" per 4K
    if card_type.lower() == "1k":
        return SocialMoscowCardConfig(social_moscow_1k_keys, 15)
    elif card_type.lower() == "4k":
        return SocialMoscowCardConfig(social_moscow_4k_keys, 15)
    else:
        return None

def social_moscow_verify(nfc_data: bytes, card_type: str) -> bool:
    config = social_moscow_get_card_config(card_type)
    if config is None:
        return False
    # Il blocco trailer del settore è al blocco: data_sector * 4 + 3
    block_num = config.data_sector * 4 + 3
    trailer = get_block(nfc_data, block_num)
    key_a = int.from_bytes(trailer[0:6], byteorder='big')
    expected_key = config.keys[config.data_sector]["a"]
    return key_a == expected_key

def social_moscow_read(nfc_data: bytes) -> bytes:
    # In questa conversione, assumiamo che nfc_data contenga già il dump completo.
    if len(nfc_data) < MAX_BLOCKS * 16:
        raise ValueError("Dump too short")
    return nfc_data

# Funzioni helper per estrarre campi da blocchi specifici
def taghash(uid: int) -> int:
    result = 0x9AE903260CC4
    uid_bytes = uid.to_bytes(UID_LEN, byteorder='little')
    for b in uid_bytes:
        result = crc64_like(result, b)
    return result

def crc64_like(result: int, sector: int) -> int:
    result ^= (sector << 40)
    for i in range(8):
        if result & 0x800000000000:
            result = ((result << 1) & 0xFFFFFFFFFFFF) ^ 0x42f0e1eba9ea3693
        else:
            result = (result << 1) & 0xFFFFFFFFFFFF
    return result

# Converte un valore esadecimale in un numero decimale interpretando ogni nibble come cifra
def hex_num(hex_val: int) -> int:
    result = 0
    multiplier = 1
    while hex_val:
        nibble = hex_val & 0xF
        result += nibble * multiplier
        multiplier *= 10
        hex_val //= 16
    return result

def calculate_luhn(number: int) -> int:
    payload = number // 10
    total_sum = 0
    position = 0
    while payload > 0:
        digit = payload % 10
        if position % 2 == 0:
            digit *= 2
        if digit > 9:
            digit = (digit // 10) + (digit % 10)
        total_sum += digit
        payload //= 10
        position += 1
    return (10 - (total_sum % 10)) % 10

def mosgortrans_parse_transport_block(block: bytes) -> str:
    # Simulazione del parsing dei dati di trasporto.
    # In una conversione completa, andrebbero implementati i dettagli specifici.
    return "Parsed transport data"

def render_section_header(header: str, width: int, indent: int) -> str:
    return header.ljust(width)

def social_moscow_parse(nfc_data: bytes, card_type: str) -> str:
    if len(nfc_data) < MAX_BLOCKS * 16:
        return "Error: dump too short."
    
    config = social_moscow_get_card_config(card_type)
    if config is None:
        return "Error: unsupported card type."
    
    # Verifica chiave: blocco trailer del settore config.data_sector
    block_num = config.data_sector * 4 + 3
    trailer = get_block(nfc_data, block_num)
    key_a = int.from_bytes(trailer[0:6], byteorder='big')
    expected_key = config.keys[config.data_sector]["a"]
    if key_a != expected_key:
        return "Error: key verification failed."
    
    # Estrai campi dal blocco 60
    block60 = get_block(nfc_data, 60)
    card_code = int.from_bytes(block60[1:4], byteorder='big')
    card_region = block60[4]
    card_number = int.from_bytes(block60[5:10], byteorder='big')
    card_control = block60[10] >> 4
    # Dal blocco 21: omc_number (8 byte a partire dal byte 1)
    block21 = get_block(nfc_data, 21)
    omc_number = int.from_bytes(block21[1:9], byteorder='big')
    year = block60[11]
    month = block60[12]
    
    number = (hex_num(card_control) +
              hex_num(card_number) * 10 +
              hex_num(card_region) * 10 * 10000000000 +
              hex_num(card_code) * 10 * 10000000000 * 100)
    
    luhn = calculate_luhn(number)
    if luhn != card_control:
        return "Error: Luhn check failed."
    
    metro_result = mosgortrans_parse_transport_block(get_block(nfc_data, 4))
    ground_result = mosgortrans_parse_transport_block(get_block(nfc_data, 16))
    
    output = (f"Social ecard\nNumber: {card_code:x} {card_region:x} {card_number:0x} {card_control:x}\n"
              f"OMC: {omc_number:x}\nValid for: {month:02x}/{year:02x} {block60[13]:02x}{block60[14]:02x}\n")
    if metro_result:
        output += render_section_header("Metro", 22, 21) + "\n" + metro_result + "\n"
    if ground_result:
        output += render_section_header("Ground", 21, 20) + "\n" + ground_result + "\n"
    return output

def main():
    if len(sys.argv) != 3:
        print("Usage: python social_moscow.py <dump_file> <card_type: 1k or 4k>")
        sys.exit(1)
    dump_file = sys.argv[1]
    card_type = sys.argv[2]
    try:
        with open(dump_file, "rb") as f:
            nfc_data = f.read()
        result = social_moscow_parse(nfc_data, card_type)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
