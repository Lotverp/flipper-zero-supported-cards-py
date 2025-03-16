#!/usr/bin/env python3
import sys
import struct

# Dimensione di un blocco (16 byte)
BLOCK_SIZE = 16

# Funzione per leggere un blocco dal dump
def get_block(card_data: bytes, block_num: int) -> bytes:
    start = block_num * BLOCK_SIZE
    return card_data[start:start + BLOCK_SIZE]

# Definizione della coppia di chiavi (in 64 bit, ma usiamo solo i 6 byte inferiori)
# Le chiavi sono espresse in esadecimale
troika_1k_keys = [
    {"a": 0xa0a1a2a3a4a5, "b": 0xfbf225dc5d58},
    {"a": 0xa82607b01c0d, "b": 0x2910989b6880},
    {"a": 0x2aa05ed1856f, "b": 0xeaac88e5dc99},
    {"a": 0x2aa05ed1856f, "b": 0xeaac88e5dc99},
    {"a": 0x73068f118c13, "b": 0x2b7f3253fac5},
    {"a": 0xfbc2793d540b, "b": 0xd3a297dc2698},
    {"a": 0x2aa05ed1856f, "b": 0xeaac88e5dc99},
    {"a": 0xae3d65a3dad4, "b": 0x0f1c63013dba},
    {"a": 0xa73f5dc1d333, "b": 0xe35173494a81},
    {"a": 0x69a32f1c2f19, "b": 0x6b8bd9860763},
    {"a": 0x9becdf3d9273, "b": 0xf8493407799d},
    {"a": 0x08b386463229, "b": 0x5efbaecef46b},
    {"a": 0xcd4c61c26e3d, "b": 0x31c7610de3b0},
    {"a": 0xa82607b01c0d, "b": 0x2910989b6880},
    {"a": 0x0e8f64340ba4, "b": 0x4acec1205d75},
    {"a": 0x2aa05ed1856f, "b": 0xeaac88e5dc99},
]

troika_4k_keys = [
    {"a": 0xEC29806D9738, "b": 0xFBF225DC5D58},
    {"a": 0xA0A1A2A3A4A5, "b": 0x7DE02A7F6025},
    {"a": 0x2AA05ED1856F, "b": 0xEAAC88E5DC99},
    {"a": 0x2AA05ED1856F, "b": 0xEAAC88E5DC99},
    {"a": 0x73068F118C13, "b": 0x2B7F3253FAC5},
    {"a": 0xFBC2793D540B, "b": 0xD3A297DC2698},
    {"a": 0x2AA05ED1856F, "b": 0xEAAC88E5DC99},
    {"a": 0xAE3D65A3DAD4, "b": 0x0F1C63013DBA},
    {"a": 0xA73F5DC1D333, "b": 0xE35173494A81},
    {"a": 0x69a32f1c2f19, "b": 0x6B8BD9860763},
    {"a": 0x9BECDF3D9273, "b": 0xF8493407799D},
    {"a": 0x08B386463229, "b": 0x5EFBAECEF46B},
    {"a": 0xCD4C61C26E3D, "b": 0x31C7610DE3B0},
    {"a": 0xA82607B01C0D, "b": 0x2910989B6880},
    {"a": 0x0E8F64340BA4, "b": 0x4ACEC1205D75},
    {"a": 0x2AA05ED1856F, "b": 0xEAAC88E5DC99},
]

# Configurazione della carta Troika
def troika_get_card_config(card_type: str):
    # card_type: "1k" o "4k"
    if card_type.lower() == "1k":
        return {"data_sector": 11, "keys": troika_1k_keys}
    elif card_type.lower() == "4k":
        return {"data_sector": 8, "keys": troika_4k_keys}
    else:
        return None

# Funzione per verificare la chiave di un settore
def troika_verify_type(nfc_data: bytes, card_type: str) -> bool:
    config = troika_get_card_config(card_type)
    if config is None:
        return False
    # Il blocco trailer del settore config["data_sector"] si trova a: (data_sector * 4 + 3)
    block_num = config["data_sector"] * 4 + 3
    trailer = get_block(nfc_data, block_num)
    # I primi 6 byte del trailer costituiscono la chiave A
    stored_key = int.from_bytes(trailer[0:6], byteorder='big')
    expected_key = config["keys"][config["data_sector"]]["a"]
    return stored_key == expected_key

def troika_verify(nfc_data: bytes, card_type: str) -> bool:
    return troika_verify_type(nfc_data, card_type)

# Funzione di lettura: verifica che il dump sia sufficientemente lungo
def troika_read(nfc_data: bytes, card_type: str) -> bool:
    # Per una carta 1K si attendono almeno 16*16=256 byte; per 4K, almeno 16*40=640 byte.
    required_length = 256 if card_type.lower() == "1k" else 640
    return len(nfc_data) >= required_length

# Funzione dummy per simulare il parsing dei dati di trasporto
def mosgortrans_parse_transport_block(block: bytes) -> str:
    # Se il blocco non è tutto 0xFF, restituisce una stringa fittizia
    if block == b'\xFF' * BLOCK_SIZE:
        return ""
    return f"Transport block data: {block.hex()}"

# Funzione di parsing della carta Troika
def troika_parse(nfc_data: bytes, card_type: str) -> str:
    config = troika_get_card_config(card_type)
    if config is None:
        return "Error: unsupported card type."
    
    # Verifica la chiave nel trailer del settore configurato
    block_num = config["data_sector"] * 4 + 3
    trailer = get_block(nfc_data, block_num)
    stored_key = int.from_bytes(trailer[0:6], byteorder='big')
    expected_key = config["keys"][config["data_sector"]]["a"]
    if stored_key != expected_key:
        return "Error: key verification failed."
    
    # Simula il parsing dei dati di trasporto da tre blocchi: 32 (Metro), 28 (Ground) e 16 (TAT)
    metro_result = mosgortrans_parse_transport_block(get_block(nfc_data, 32))
    ground_result = mosgortrans_parse_transport_block(get_block(nfc_data, 28))
    tat_result = mosgortrans_parse_transport_block(get_block(nfc_data, 16))
    
    output = "Troyka card\n"
    if metro_result:
        output += metro_result + "\n"
    if ground_result:
        output += ground_result + "\n"
    if tat_result:
        output += tat_result + "\n"
    return output

def main():
    if len(sys.argv) != 3:
        print("Usage: python troika.py <dump_file> <card_type: 1k or 4k>")
        sys.exit(1)
    dump_file = sys.argv[1]
    card_type = sys.argv[2]
    try:
        with open(dump_file, "rb") as f:
            nfc_data = f.read()
        if not troika_read(nfc_data, card_type):
            print("Error: card dump too short.")
            sys.exit(1)
        if not troika_verify(nfc_data, card_type):
            print("Error: card verification failed.")
            sys.exit(1)
        result = troika_parse(nfc_data, card_type)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
