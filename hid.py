#!/usr/bin/env python3
import sys

MF_CLASSIC_BLOCK_SIZE = 16
UID_LENGTH = 7
# HID key costante: 0x484944204953 (in ASCII "HID IS")
HID_KEY = 0x484944204953

def get_block(card_data: bytes, block_num: int) -> bytes:
    """Restituisce il blocco 'block_num' (ogni blocco è di 16 byte)."""
    start = block_num * MF_CLASSIC_BLOCK_SIZE
    return card_data[start:start+MF_CLASSIC_BLOCK_SIZE]

def get_sector_trailer(card_data: bytes, sector: int) -> bytes:
    """Restituisce il blocco trailer del settore (settore * 4 + 3)."""
    trailer_block = sector * 4 + 3
    return get_block(card_data, trailer_block)

def reverse_bytes_u32(x: int) -> int:
    """Byteswap a 32-bit integer."""
    return ((x & 0xFF) << 24) | (((x >> 8) & 0xFF) << 16) | (((x >> 16) & 0xFF) << 8) | ((x >> 24) & 0xFF)

def reverse_bytes_64(x: int) -> int:
    """Byteswap a 64-bit integer."""
    b = x.to_bytes(8, byteorder='little')
    return int.from_bytes(b, byteorder='big')

def clz(x: int) -> int:
    """Restituisce il numero di zeri iniziali in una rappresentazione a 32 bit."""
    return 32 - x.bit_length() if x != 0 else 32

def get_bit_length(half_block: bytes) -> int:
    """
    Calcola la lunghezza in bit del campo PACS.
    - half_block è una sequenza di 8 byte.
    - Se i primi 4 byte (h0) sono 0, si calcola: bitLength = 31 - clz(byteswap(h1))
    - Altrimenti: bitLength = 63 - clz(byteswap(h0))
    """
    if len(half_block) < 8:
        return 0
    h0 = int.from_bytes(half_block[0:4], byteorder='big')
    h1 = int.from_bytes(half_block[4:8], byteorder='big')
    if h0 == 0:
        leading0s = clz(reverse_bytes_u32(h1))
        bitLength = 31 - leading0s
    else:
        leading0s = clz(reverse_bytes_u32(h0))
        bitLength = 63 - leading0s
    return bitLength

def get_pacs_bits(block: bytes, bitLength: int) -> int:
    """
    Estrae il valore dei PACS bits:
      - Calcola un sentinel = byteswap_64(1 << bitLength)
      - Legge 8 byte da block come un intero a 64 bit (big endian)
      - Effettua XOR con il sentinel, poi byteswap a 64 bit.
    """
    if len(block) < 8:
        return 0
    sentinel = reverse_bytes_64(1 << bitLength)
    raw = int.from_bytes(block[:8], byteorder='big')
    swapped = reverse_bytes_64(raw ^ sentinel)
    return swapped

def hid_verify(card_data: bytes) -> bool:
    """
    Verifica la carta HID controllando che la chiave (Key A) memorizzata
    nel trailer del settore 1 corrisponda al valore HID_KEY.
    """
    # Per settore 1, il trailer si trova nel blocco: 1*4+3 = 7
    trailer = get_sector_trailer(card_data, 1)
    # I primi 6 byte rappresentano la chiave A
    stored_key = int.from_bytes(trailer[:6], byteorder='big')
    return stored_key == HID_KEY

def hid_read(card_data: bytes) -> bool:
    """
    Simula la lettura della carta. In questa conversione, si assume che
    il dump sia già fornito. Se il dump ha lunghezza sufficiente, restituisce True.
    """
    return len(card_data) >= 1024

def hid_parse(card_data: bytes) -> str:
    """
    Esegue il parsing di una HID Card.
    - Verifica che la chiave memorizzata nel trailer del settore 1 (blocco 7)
      corrisponda a HID_KEY.
    - Estrae dal blocco 5 (settore 1) a partire dall’offset 8 un campo di 8 byte.
    - Calcola la lunghezza in bit e, utilizzando una sentinel, estrae il valore dei PACS bits.
    - Restituisce una stringa formattata con il numero di bit e il valore in esadecimale.
    """
    # Verifica la chiave
    if not hid_verify(card_data):
        return "Errore: verifica chiave fallita."
    
    # Estrae il blocco 5 (secondo blocco del settore 1: settore 1 contiene blocchi 4-7)
    block5 = get_block(card_data, 5)
    # Usa i byte da offset 8 a 16 (8 byte)
    credential_block = block5[8:16]
    bit_length = get_bit_length(credential_block)
    if bit_length == 0:
        return "Errore: lunghezza bit pari a 0."
    credential = get_pacs_bits(credential_block, bit_length)
    if credential == 0:
        return "Errore: credential pari a 0."
    
    result = f"HID Card\n{bit_length}bit\n{credential:0{(bit_length+3)//4}X}"
    return result

def main():
    if len(sys.argv) != 2:
        print("Uso: python hid.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        if not hid_read(card_data):
            print("Errore: dump della carta troppo corto (atteso 1024 byte per una 1K).")
            sys.exit(1)
        result = hid_parse(card_data)
        print(result)
    except Exception as e:
        print("Errore:", e)

if __name__ == '__main__':
    main()
