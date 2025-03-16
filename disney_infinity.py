#!/usr/bin/env python3
import sys
import hashlib

UID_LEN = 7

# Array seed derivato da https://nfc.toys/#new-interoperability-for-infinity
SEED = bytearray([
    0x0A, 0x14, 0xFD, 0x05, 0x07, 0xFF, 0x4B, 0xCD, 0x02, 0x6B,
    0xA8, 0x3F, 0x0A, 0x3B, 0x89, 0xA9, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x28, 0x63, 0x29, 0x20, 0x44, 0x69, 0x73,
    0x6E, 0x65, 0x79, 0x20, 0x32, 0x30, 0x31, 0x33
])

def di_key(uid: bytes) -> bytes:
    """
    Calcola la chiave Disney Infinity:
    - Copia i primi UID_LEN byte dell'UID in SEED a partire dall'offset 16.
    - Calcola l'hash SHA-1 del seed modificato.
    - La chiave (6 byte) è composta da:
        key[0] = hash[3]
        key[1] = hash[2]
        key[2] = hash[1]
        key[3] = hash[0]
        key[4] = hash[7]
        key[5] = hash[6]
    """
    seed_copy = bytearray(SEED)  # copia per non modificare l'originale
    seed_copy[16:16+UID_LEN] = uid[:UID_LEN]
    hash_val = hashlib.sha1(seed_copy).digest()  # 20 byte
    key = bytearray(6)
    key[0] = hash_val[3]
    key[1] = hash_val[2]
    key[2] = hash_val[1]
    key[3] = hash_val[0]
    key[4] = hash_val[7]
    key[5] = hash_val[6]
    return bytes(key)

def get_block(card_data: bytes, block_num: int) -> bytes:
    """
    Restituisce il blocco 'block_num' (ogni blocco è di 16 byte).
    """
    start = block_num * 16
    return card_data[start:start+16]

def get_uid(card_data: bytes) -> bytes:
    """
    Estrae l'UID dalla carta: si assume sia memorizzato nel blocco 0, primi UID_LEN byte.
    """
    block0 = get_block(card_data, 0)
    return block0[:UID_LEN]

def get_sector_trailer(card_data: bytes, sector: int) -> bytes:
    """
    Restituisce il blocco trailer del settore specificato.
    Per una Mifare Classic 1K, il trailer del settore è al blocco (sector*4 + 3).
    """
    trailer_block = sector * 4 + 3
    return get_block(card_data, trailer_block)

def disney_infinity_parse(card_data: bytes) -> str:
    """
    Esegue il parsing del dump di una Disney Infinity card.
    Verifica la chiave calcolata tramite di_key con quella memorizzata nel settore trailer (Key A) del settore 0.
    """
    # Controlla che il dump sia di almeno 1024 byte (1K)
    if len(card_data) < 1024:
        return "Errore: dump della carta troppo corto."
    
    uid = get_uid(card_data)
    computed_key = di_key(uid)
    
    # Recupera la chiave memorizzata (Key A) dal trailer del settore 0 (blocco 3)
    sector0_trailer = get_sector_trailer(card_data, 0)
    stored_keyA = sector0_trailer[:6]
    
    if computed_key != stored_keyA:
        return "Errore: verifica chiave fallita."
    
    output = "Disney Infinity\n"
    output += f"UID: {uid.hex()}\n"
    output += "Verifica chiave riuscita."
    return output

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Uso: python disney_infinity.py <dump_file>")
        sys.exit(1)
    
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        result = disney_infinity_parse(card_data)
        print(result)
    except Exception as e:
        print("Errore nella lettura del file:", e)
