#!/usr/bin/env python3
import sys

BLOCK_SIZE = 16
MAX_BLOCKS = 64

# Chiavi per TwoCities (4K) (solo un array, utilizzato per tutte le sezioni)
two_cities_4k_keys = [
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0x2aa05ed1856f, "b": 0xeaac88e5dc99},
    {"a": 0x2aa05ed1856f, "b": 0xeaac88e5dc99},
    {"a": 0xe56ac127dd45, "b": 0x19fc84a3784b},
    {"a": 0x77dabc9825c,   "b": 0x9764fec3154a},  # Nota: 0x77dabc9825c equivale a 0x77dabc9825e1 (eventuale errore di trascrizione, qui usiamo il valore originale)
    {"a": 0x2aa05ed1856f, "b": 0xeaac88e5dc99},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xa73f5dc1d333, "b": 0xe35173494a81},
    {"a": 0x69a32f1c2f19, "b": 0x6b8bd9860763},
    {"a": 0xea0fd73cb149, "b": 0x29c35fa068fb},
    {"a": 0xc76bf71a2509, "b": 0x9ba241db3f56},
    {"a": 0xacffffffffff, "b": 0x71f3a315ad26},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0x2aa05ed1856f, "b": 0xeaac88e5dc99},
    {"a": 0x72f96bdd3714, "b": 0x462225cd34cf},
    {"a": 0x044ce1872bc3, "b": 0x8c90c70cff4a},
    {"a": 0xbc2d1791dec1, "b": 0xca96a487de0b},
    {"a": 0x8791b2ccb5c4, "b": 0xc956c3b80da3},
    {"a": 0x8e26e45e7d65, "b": 0x8e65b3af7d22},
    {"a": 0x0f318130ed18, "b": 0x0c420a20e056},
    {"a": 0x045ceca15535, "b": 0x31bec3d9e510},
    {"a": 0x9d993c5d4ef4, "b": 0x86120e488abf},
    {"a": 0xc65d4eaa645b, "b": 0xb69d40d1a439},
    {"a": 0x3a8a139c20b4, "b": 0x8818a9c5d406},
    {"a": 0xbaff3053b496, "b": 0x4b7cb25354d3},
    {"a": 0x7413b599c4ea, "b": 0xb0a2aaf3a1ba},
    {"a": 0x0ce7cd2cc72b, "b": 0xfa1fbb3f0f1f},
    {"a": 0x0be5fac8b06a, "b": 0x6f95887a4fd3},
    {"a": 0x26973ea74321, "b": 0xd27058c6e2c7},
    {"a": 0xeb0a8ff88ade, "b": 0x578a9ada41e3},
    {"a": 0x7a396f0d633d, "b": 0xad2bdc097023},
    {"a": 0xa3faa6daff67, "b": 0x7600e889adf9},
    {"a": 0x2aa05ed1856f, "b": 0xeaac88e5dc99},
    {"a": 0x2aa05ed1856f, "b": 0xeaac88e5dc99},
    {"a": 0xa7141147d430, "b": 0xff16014fefc7},
    {"a": 0x8a8d88151a00, "b": 0x038b5f9b5a2a},
    {"a": 0xb27addfb64b0, "b": 0x152fd0c420a7},
    {"a": 0x7259fa0197c6, "b": 0x5583698df085},
]

def two_cities_verify(nfc_data: bytes) -> bool:
    """
    Verifica la chiave nel settore 4 della carta TwoCities.
    """
    verify_sector = 4
    block_num = verify_sector * 4 + 3  # blocco trailer del settore 4
    trailer = nfc_data[block_num * BLOCK_SIZE:(block_num + 1) * BLOCK_SIZE]
    stored_key = int.from_bytes(trailer[0:6], byteorder='big')
    expected_key = two_cities_4k_keys[verify_sector]["a"]
    return stored_key == expected_key

def two_cities_read(nfc_data: bytes) -> bool:
    """
    Verifica che il dump sia sufficientemente lungo.
    """
    return len(nfc_data) >= MAX_BLOCKS * BLOCK_SIZE

def two_cities_parse(nfc_data: bytes) -> str:
    """
    Parser per le TwoCities card:
      - Estrae il saldo dalla sezione "Plantain" (dal blocco 16)
      - Estrae l'UID dalla sezione "Plantain" (dal blocco 0)
      - Estrae il troika number e troika balance dalla sezione "Troika" (dal blocco 32 e 33)
      - Formattta l’output.
    """
    # Verifica chiave nel settore 4
    sector = 4
    trailer_block_num = sector * 4 + 3
    trailer = nfc_data[trailer_block_num * BLOCK_SIZE:(trailer_block_num + 1) * BLOCK_SIZE]
    stored_key = int.from_bytes(trailer[0:6], byteorder='big')
    if stored_key != two_cities_4k_keys[sector]["a"]:
        return "Error: key verification failed."
    
    # Sezione "Plantain": blocco 16 contiene il saldo
    block16 = nfc_data[16 * BLOCK_SIZE:(16 + 1) * BLOCK_SIZE]
    # I primi 4 byte del blocco, in ordine invertito, formano il saldo (diviso per 100)
    balance_bytes = block16[0:4][::-1]
    balance = int.from_bytes(balance_bytes, byteorder='big') // 100
    
    # Estrai UID dalla sezione "Plantain": dal blocco 0, primi 7 byte invertiti
    block0 = nfc_data[0:BLOCK_SIZE]
    uid_bytes = block0[0:7][::-1]
    card_number = int.from_bytes(uid_bytes, byteorder='big')
    
    # Sezione "Troika": 
    # Dal blocco 33, a partire dal byte 5, leggi 4 byte per il troika balance, 
    # interpretati come big-endian e divisi per 25.
    block33 = nfc_data[33 * BLOCK_SIZE:(33 + 1) * BLOCK_SIZE]
    troika_balance = int.from_bytes(block33[5:7], byteorder='big') // 25
    # Dal blocco 32, a partire dal byte 2, leggi 4 byte (big-endian) e shift right di 4 bit per il troika number
    block32 = nfc_data[32 * BLOCK_SIZE:(32 + 1) * BLOCK_SIZE]
    troika_number = int.from_bytes(block32[2:6], byteorder='big') >> 4
    
    output_lines = [
        "TwoCities card",
        f"PN: {card_number}X",
        f"PB: {balance} rur.",
        f"TN: {troika_number}",
        f"TB: {troika_balance} rur."
    ]
    return "\n".join(output_lines)

def main():
    if len(sys.argv) != 2:
        print("Usage: python two_cities.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            nfc_data = f.read()
        if not two_cities_read(nfc_data):
            print("Error: card dump too short.")
            sys.exit(1)
        if not two_cities_verify(nfc_data):
            print("Error: card verification failed.")
            sys.exit(1)
        result = two_cities_parse(nfc_data)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
