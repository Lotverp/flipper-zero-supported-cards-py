#!/usr/bin/env python3
import sys
import struct

# Costanti
KEY_LENGTH = 6
HI_KEY_TO_GEN = 5
UID_LENGTH = 7
TOTAL_SECTORS_1K = 16  # Mifare Classic 1K

MF_CLASSIC_BLOCK_SIZE = 16

# hi_1k_keys: array di 16 coppie (a, b). Gli elementi per i settori 1,2,3,4 sono inizialmente a zero.
hi_1k_keys = [
    {"a": 0xA0A1A2A3A4A5, "b": 0x30871CF60CF1},  # Sector 0
    {"a": 0x000000000000, "b": 0x000000000000},  # Sector 1
    {"a": 0x000000000000, "b": 0x000000000000},  # Sector 2
    {"a": 0x000000000000, "b": 0x000000000000},  # Sector 3
    {"a": 0x000000000000, "b": 0x000000000000},  # Sector 4
    {"a": 0x42FFE4C76209, "b": 0x7B30CFD04CBD},  # Sector 5
    {"a": 0x01ED8145BDF8, "b": 0x92257F472FCE},  # Sector 6
    {"a": 0x7583A07D21A6, "b": 0x51CA6EA8EE26},  # Sector 7
    {"a": 0x1E10BF5D6A1D, "b": 0x87B9B9BFABA6},  # Sector 8
    {"a": 0xF9DB1B2B21BA, "b": 0x80A781F4134C},  # Sector 9
    {"a": 0x7F5283FACB72, "b": 0x73250009D75A},  # Sector 10
    {"a": 0xE48E86A03078, "b": 0xCFFBBF08A254},  # Sector 11
    {"a": 0x39AB26301F60, "b": 0xC71A6E532C83},  # Sector 12
    {"a": 0xAD656C6C639F, "b": 0xFD9819CBD20A},  # Sector 13
    {"a": 0xF0E15160DB3E, "b": 0x3F622D515ADD},  # Sector 14
    {"a": 0x03F44E033C42, "b": 0x61E897875F46},  # Sector 15
]

# Funzione per estrarre un blocco da card_data
def get_block(card_data: bytes, block_num: int) -> bytes:
    start = block_num * MF_CLASSIC_BLOCK_SIZE
    return card_data[start:start+MF_CLASSIC_BLOCK_SIZE]

# HI Key Derivation Function (KDF)
def hi_generate_key(uid: bytes):
    # Tabelle XOR per keyB e keyA (4 tabelle da 6 byte ciascuna)
    xor_table_keyB = [
        [0x1F, 0xC4, 0x4D, 0x94, 0x6A, 0x31],
        [0x12, 0xC1, 0x5C, 0x70, 0xDF, 0x31],
        [0x56, 0xF0, 0x13, 0x1B, 0x63, 0xF2],
        [0x4E, 0xFA, 0xC2, 0xF8, 0xC9, 0xCC],
    ]
    xor_table_keyA = [
        [0xB6, 0xE6, 0xAE, 0x72, 0x91, 0x0D],
        [0x6D, 0x38, 0x50, 0xFB, 0x42, 0x89],
        [0x1E, 0x5F, 0xC7, 0xED, 0xAA, 0x02],
        [0x7E, 0xB9, 0xCA, 0xF1, 0x9C, 0x59],
    ]
    xorOrderA = [0, 1, 2, 3, 0, 2]
    xorOrderB = [1, 3, 3, 2, 1, 0]

    # Creiamo due liste di HI_KEY_TO_GEN elementi (ci aspettiamo 5)
    keyA = [bytearray(6) for _ in range(HI_KEY_TO_GEN)]
    keyB = [bytearray(6) for _ in range(HI_KEY_TO_GEN)]
    # Genera le chiavi per j = 1,2,3,4 (gli indici 1..4)
    for j in range(1, HI_KEY_TO_GEN):
        for i in range(KEY_LENGTH):
            keyA[j][i] = uid[xorOrderA[i]] ^ xor_table_keyA[j - 1][i]
            keyB[j][i] = uid[xorOrderB[i]] ^ xor_table_keyB[j - 1][i]
    # Converti in bytes
    keyA = [bytes(k) for k in keyA]
    keyB = [bytes(k) for k in keyB]
    return keyA, keyB

# Funzione per ottenere la configurazione della carta HI!
def hi_get_card_config(card_type: str):
    # Nel nostro caso, supportiamo solo 1K
    if card_type != "1K":
        return None
    return {"verify_sector": 0, "keys": hi_1k_keys}

# Simula la verifica: controlla il settore di verifica (settore 0)
def hi_verify(card_data: bytes) -> bool:
    # Ottieni la configurazione
    cfg = hi_get_card_config("1K")
    if not cfg:
        return False
    # Per una carta 1K, il trailer del settore 0 è nel blocco 3
    trailer_block = get_block(card_data, 3)
    # I primi 6 byte del trailer rappresentano la chiave A; qui, invece, vogliamo verificare la chiave B memorizzata.
    # In questa simulazione assumiamo che la chiave B memorizzata sia nei byte 6-11 del blocco trailer.
    stored_keyB = int.from_bytes(trailer_block[6:12], byteorder='big')
    expected_keyB = cfg["keys"][cfg["verify_sector"]]["b"]
    return stored_keyB == expected_keyB

# Simula la lettura della carta: aggiorna le chiavi per i settori con valore zero
def hi_read(card_data: bytes) -> bool:
    cfg = hi_get_card_config("1K")
    if not cfg:
        return False
    # Estrai UID dalla "iso14443_3a_data" simulata: assumiamo che sia nei primi UID_LENGTH byte del dump
    uid = card_data[0:UID_LENGTH]
    # Genera le chiavi A e B basate sull'UID
    gen_keyA, gen_keyB = hi_generate_key(uid)
    # Aggiorna la configurazione: per i settori 0..(HI_KEY_TO_GEN-1) se le chiavi sono zero, usale generate
    for i in range(TOTAL_SECTORS_1K):
        if cfg["keys"][i]["a"] == 0 and cfg["keys"][i]["b"] == 0:
            if i < HI_KEY_TO_GEN:
                # Converti la chiave (bytes) in un intero big endian
                cfg["keys"][i]["a"] = int.from_bytes(gen_keyA[i], byteorder='big')
                cfg["keys"][i]["b"] = int.from_bytes(gen_keyB[i], byteorder='big')
    # In una vera lettura verrebbe usata la struttura "keys" per decrittare i settori;
    # in questa simulazione consideriamo la lettura riuscita se non ci sono errori.
    return True

# Parsing: estrae l'UID e lo formatta
def hi_parse(card_data: bytes) -> str:
    cfg = hi_get_card_config("1K")
    if not cfg:
        return "Tipo di carta non supportato."
    # Verifica la chiave nel settore di verifica (settore 0): utilizza il blocco trailer (blocco 3)
    trailer_block = get_block(card_data, 3)
    stored_keyB = int.from_bytes(trailer_block[6:12], byteorder='big')
    if stored_keyB != cfg["keys"][cfg["verify_sector"]]["b"]:
        return "Errore nella verifica della chiave."
    # Estrai UID: assumiamo che sia nei primi UID_LENGTH byte del dump
    uid = card_data[0:UID_LENGTH]
    uid_str = " ".join(f"{b:02X}" for b in uid)
    output = "HI! Card\n"
    output += f"UID:{uid_str}\n"
    return output

# Funzione principale
def main():
    if len(sys.argv) != 2:
        print("Uso: python hi.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        if len(card_data) < 1024:
            print("Errore: dump della carta troppo corto (atteso 1024 byte per una 1K).")
            sys.exit(1)
        
        # Simula verifica
        if not hi_verify(card_data):
            print("Verifica della carta fallita: non è una HI! Card oppure la chiave non corrisponde.")
            sys.exit(1)
        
        # Simula lettura (aggiornamento delle chiavi)
        if not hi_read(card_data):
            print("Errore durante la lettura della carta.")
            sys.exit(1)
        
        # Parsing: ottieni stringa formattata
        result = hi_parse(card_data)
        print(result)
    except Exception as e:
        print("Errore:", e)

if __name__ == '__main__':
    main()
