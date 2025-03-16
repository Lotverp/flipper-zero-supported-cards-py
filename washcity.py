#!/usr/bin/env python3
import sys

BLOCK_SIZE = 16
TOTAL_BLOCKS_1K = 64  # Mifare Classic 1K: 64 blocchi

def get_block(data: bytes, block_num: int) -> bytes:
    """Restituisce il blocco di 16 byte corrispondente al numero di blocco."""
    start = block_num * BLOCK_SIZE
    return data[start:start+BLOCK_SIZE]

def bytes_to_int_be(b: bytes) -> int:
    """Converte una sequenza di byte (big-endian) in intero."""
    return int.from_bytes(b, byteorder='big')

# Chiavi per WashCity (Mifare Classic 1K) per ciascun settore (0..15)
washcity_1k_keys = [
    {"a": 0xA0A1A2A3A4A5, "b": 0x010155010100},  # Sector 00
    {"a": 0xC78A3D0E1BCD, "b": 0xFFFFFFFFFFFF},  # Sector 01
    {"a": 0xC78A3D0E0000, "b": 0xFFFFFFFFFFFF},  # Sector 02
    {"a": 0xC78A3D0E0000, "b": 0xFFFFFFFFFFFF},  # Sector 03
    {"a": 0xC78A3D0E0000, "b": 0xFFFFFFFFFFFF},  # Sector 04
    {"a": 0xC78A3D0E0000, "b": 0xFFFFFFFFFFFF},  # Sector 05
    {"a": 0xC78A3D0E0000, "b": 0xFFFFFFFFFFFF},  # Sector 06
    {"a": 0xC78A3D0E0000, "b": 0xFFFFFFFFFFFF},  # Sector 07
    {"a": 0xC78A3D0E0000, "b": 0xFFFFFFFFFFFF},  # Sector 08
    {"a": 0x010155010100, "b": 0xFFFFFFFFFFFF},  # Sector 09
    {"a": 0x010155010100, "b": 0xFFFFFFFFFFFF},  # Sector 10
    {"a": 0x010155010100, "b": 0xFFFFFFFFFFFF},  # Sector 11
    {"a": 0x010155010100, "b": 0xFFFFFFFFFFFF},  # Sector 12
    {"a": 0x010155010100, "b": 0xFFFFFFFFFFFF},  # Sector 13
    {"a": 0x010155010100, "b": 0xFFFFFFFFFFFF},  # Sector 14
    {"a": 0x010155010100, "b": 0xFFFFFFFFFFFF},  # Sector 15
]

def washcity_verify(nfc_data: bytes) -> bool:
    """
    Verifica la chiave del settore 1:
    Il blocco trailer del settore 1 (settore 1 * 4 + 0) deve contenere, nei primi 6 byte, la chiave attesa.
    """
    verify_sector = 1
    # Il trailer del settore 1 si trova nel blocco: sector * 4 + 0 (in questo caso ticket_block_number = 0)
    block_num = verify_sector * 4
    trailer = get_block(nfc_data, block_num)
    stored_key = int.from_bytes(trailer[0:6], byteorder='big')
    expected_key = washcity_1k_keys[verify_sector]["a"]
    return stored_key == expected_key

def washcity_read(nfc_data: bytes) -> bool:
    """Verifica che il dump sia sufficientemente lungo."""
    return len(nfc_data) >= TOTAL_BLOCKS_1K * BLOCK_SIZE

def washcity_parse(nfc_data: bytes) -> str:
    """
    Parser per la WashCity MarkItaly Card:
      - Verifica la chiave nel settore 1.
      - Legge il saldo dal blocco 0 del settore 1 (a partire dal byte 2, 2 byte, big-endian).
      - Estrae l’UID (card number) dal dump (qui usiamo i primi 4 byte).
      - Formattta l’output con il numero della carta in esadecimale e il saldo in EUR.
    """
    if not washcity_verify(nfc_data):
        return "Error: key verification failed."
    
    ticket_sector = 1
    start_block_num = ticket_sector * 4  # Primo blocco del settore 1
    block = get_block(nfc_data, start_block_num)
    # Il saldo è memorizzato a partire dal byte 2 (2 byte in big-endian)
    balance_val = bytes_to_int_be(block[2:4])
    balance_usd = balance_val // 100
    balance_cents = balance_val % 100
    
    # L'UID (card number) si assume sia nei primi 4 byte del dump.
    uid = nfc_data[0:4]
    card_number = bytes_to_int_be(uid)
    
    output = (
        "WashCity MarkItaly Card\n"
        f"Card number: {card_number:0{len(uid)*2}X}\n"
        f"Balance: {balance_usd}.{balance_cents:02d} EUR"
    )
    return output

def main():
    if len(sys.argv) != 2:
        print("Usage: python washcity.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            nfc_data = f.read()
        if not washcity_read(nfc_data):
            print("Error: card dump too short.")
            sys.exit(1)
        result = washcity_parse(nfc_data)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
