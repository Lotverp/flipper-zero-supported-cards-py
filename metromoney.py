#!/usr/bin/env python3
import sys

# Dimensione di un blocco e dump atteso per una Mifare Classic 1K
MF_CLASSIC_BLOCK_SIZE = 16
EXPECTED_DUMP_SIZE = 1024

# Funzione helper per estrarre un blocco (16 byte) dal dump
def get_block(card_data: bytes, block_num: int) -> bytes:
    start = block_num * MF_CLASSIC_BLOCK_SIZE
    return card_data[start:start + MF_CLASSIC_BLOCK_SIZE]

# Funzioni per leggere un numero dai byte (little-endian e big-endian)
def get_number_le(data: bytes, start: int, length: int) -> int:
    return int.from_bytes(data[start:start+length], byteorder='little')

def get_number_be(data: bytes, start: int, length: int) -> int:
    return int.from_bytes(data[start:start+length], byteorder='big')

# Array di chiavi predefinite per le carte Metromoney (1K)
metromoney_1k_keys = [
    {"a": 0x2803BCB0C7E1, "b": 0x4FA9EB49F75E},
    {"a": 0x9C616585E26D, "b": 0xD1C71E590D16},
    {"a": 0x9C616585E26D, "b": 0xA160FCD5EC4C},
    {"a": 0x9C616585E26D, "b": 0xA160FCD5EC4C},
    {"a": 0x9C616585E26D, "b": 0xA160FCD5EC4C},
    {"a": 0x9C616585E26D, "b": 0xA160FCD5EC4C},
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},
    {"a": 0x112233445566, "b": 0x361A62F35BC9},
    {"a": 0x112233445566, "b": 0x361A62F35BC9},
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},
]

def metromoney_verify(card_data: bytes) -> bool:
    """
    Verifica la carta Metromoney autenticando il settore dei ticket (settore 1).
    In particolare, legge il blocco trailer del settore 1 (blocco 7) e confronta i primi 6 byte
    (Key A) con la chiave attesa per il settore 1.
    """
    ticket_sector = 1
    # Il blocco trailer del settore 1 è al blocco: (sector 1 * 4 + 3)
    trailer_block = get_block(card_data, ticket_sector * 4 + 3)
    stored_key = int.from_bytes(trailer_block[0:6], byteorder='big')
    expected_key = metromoney_1k_keys[ticket_sector]["a"]
    return stored_key == expected_key

def metromoney_read(card_data: bytes) -> bool:
    """Verifica che il dump abbia la lunghezza attesa."""
    return len(card_data) >= EXPECTED_DUMP_SIZE

def metromoney_parse(card_data: bytes) -> str:
    """
    Esegue il parsing della Metromoney card:
    - Dal settore dei ticket (settore 1) estrae il blocco 1 (all'interno del settore)
      e legge i primi 4 byte come saldo (in little endian), sottrae 100.
    - Il saldo viene poi suddiviso in dollari (lari) e centesimi (tetri).
    - L’UID della carta viene estratto dai primi 4 byte del dump e interpretato come numero di carta.
    - Viene restituito un output formattato con il numero della carta e il saldo in GEL.
    """
    if len(card_data) < EXPECTED_DUMP_SIZE:
        return "Error: Card dump too short."
    
    # Il settore dei ticket è 1.
    ticket_sector = 1
    # Nel C originale viene usato "ticket_block_number = 1", ovvero il blocco in posizione 1 all'interno del settore.
    start_block = ticket_sector * 4  # In un 1K, settore 1 inizia a blocco 4.
    ticket_block = get_block(card_data, start_block + 1)
    
    # Legge il saldo: 4 byte in little endian, quindi sottrae 100
    balance_raw = int.from_bytes(ticket_block[0:4], byteorder='little')
    balance = balance_raw - 100
    balance_lari = balance // 100
    balance_tetri = balance % 100
    
    # Estrae l'UID della carta: si assume sia nei primi 4 byte del dump
    uid = card_data[0:4]
    card_number = int.from_bytes(uid, byteorder='little')
    
    output = f"Metromoney\nCard number: {card_number}\nBalance: {balance_lari}.{balance_tetri:02d} GEL"
    return output

def main():
    if len(sys.argv) != 2:
        print("Usage: python metromoney.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        if not metromoney_read(card_data):
            print("Error: Card dump too short")
            sys.exit(1)
        if not metromoney_verify(card_data):
            print("Error: Verification failed")
            sys.exit(1)
        result = metromoney_parse(card_data)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
