#!/usr/bin/env python3
import sys

# Costanti: dimensione chiave e UID atteso
KEY_LENGTH = 6
UID_LENGTH = 4
MF_CLASSIC_BLOCK_SIZE = 16
EXPECTED_DUMP_SIZE = 1024

# Array di chiavi per Microel (inizialmente impostate a 0 per alcuni settori)
microel_1k_keys = [
    {"a": 0x000000000000, "b": 0x000000000000},  # Settore 0
    {"a": 0x000000000000, "b": 0x000000000000},  # Settore 1
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 2
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 3
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 4
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 5
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 6
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 7
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 8
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 9
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 10
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 11
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 12
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 13
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 14
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # Settore 15
]

# Settore usato per la verifica della chiave
VERIFY_SECTOR = 1

# --- Funzioni KDF per Microel cards ---

def calculate_sum_hex(uid: bytes) -> bytes:
    """
    Somma i byte dell'UID, calcola il modulo 256, aggiunge 2 se il risultato è dispari,
    e quindi esegue XOR con un xorKey fisso per ottenere 6 byte.
    """
    xor_key = bytes([0x01, 0x92, 0xA7, 0x75, 0x2B, 0xF9])
    s = sum(uid) % 256
    if s % 2 == 1:
        s += 2
    # XOR ogni byte del valore (ripetuto come costante) con il corrispondente byte dell'xor_key
    return bytes([s ^ xor_key[i] for i in range(6)])

def generate_keyA(uid: bytes) -> bytes:
    """
    Genera Key A in base all'UID:
      - Calcola sumHex dai 4 byte di uid.
      - Se il nibble alto del primo byte (sumHex[0]) è in {2,3,A,B}, allora keyA = 0x40 XOR sumHex.
      - Se è in {6,7,E,F}, allora keyA = 0xC0 XOR sumHex.
      - Altrimenti, keyA = sumHex.
    """
    sum_hex = calculate_sum_hex(uid)
    first_nibble = (sum_hex[0] >> 4) & 0xF
    if first_nibble in (0x2, 0x3, 0xA, 0xB):
        return bytes([0x40 ^ b for b in sum_hex])
    elif first_nibble in (0x6, 0x7, 0xE, 0xF):
        return bytes([0xC0 ^ b for b in sum_hex])
    else:
        return sum_hex

def generate_keyB(keyA: bytes) -> bytes:
    """
    Genera Key B come complemento (XOR con 0xFF) di Key A.
    """
    return bytes([0xFF ^ b for b in keyA])

# --- Funzioni per leggere dati dal dump ---

def get_block(card_data: bytes, block_num: int) -> bytes:
    """Restituisce il blocco 'block_num' (ogni blocco è 16 byte)."""
    start = block_num * MF_CLASSIC_BLOCK_SIZE
    return card_data[start:start+MF_CLASSIC_BLOCK_SIZE]

# Simula la lettura: si aspetta un dump di almeno 1024 byte.
def microel_read(card_data: bytes) -> bool:
    if len(card_data) < EXPECTED_DUMP_SIZE:
        return False

    # Ottiene l'UID; qui si assume che sia nei primi 4 byte del dump.
    uid = card_data[0:UID_LENGTH]
    if len(uid) != UID_LENGTH:
        return False

    # Genera le chiavi
    key_a = generate_keyA(uid)
    key_b = generate_keyB(key_a)

    # Per il settore 0 (blocco 0), prova ad autenticare con Key A
    # (in questa conversione, simuliamo l'autenticazione controllando se la chiave generata è valida)
    # Se l'autenticazione ha successo, aggiorniamo i valori nelle chiavi predefinite per i settori che sono zero.
    # Qui simuliamo tale aggiornamento per i settori 0..(numero totale - 1)
    total_sectors = 16
    for i in range(total_sectors):
        if microel_1k_keys[i]["a"] == 0:
            microel_1k_keys[i]["a"] = int.from_bytes(key_a, byteorder='big')
        if microel_1k_keys[i]["b"] == 0:
            microel_1k_keys[i]["b"] = int.from_bytes(key_b, byteorder='big')
    # In un ambiente reale verrebbe eseguita l'autenticazione; qui consideriamo la lettura riuscita.
    return True

# Funzione per il parsing dei dati (estrazione dell'UID e dei crediti)
def microel_parse(card_data: bytes) -> str:
    if len(card_data) < EXPECTED_DUMP_SIZE:
        return "Errore: dump della carta troppo corto."
    
    # Ottiene l'UID
    uid = card_data[0:UID_LENGTH]
    if len(uid) != UID_LENGTH:
        return "Errore: UID non valido."
    
    # Rigenera Key A dal uid
    keyA_generated = generate_keyA(uid)
    
    # Legge il blocco trailer del settore di verifica (settore 1: blocco = 1*4+3 = 7)
    trailer_block = get_block(card_data, VERIFY_SECTOR * 4 + 3)
    stored_key = int.from_bytes(trailer_block[0:6], byteorder='big')
    generated_key = int.from_bytes(keyA_generated, byteorder='big')
    if stored_key != generated_key:
        return "Errore: chiave non verificata."
    
    # Estrae i crediti. Dal blocco 4 (settore 1) si prende il blocco con indice 4
    # Qui, il credito corrente è formato da 2 byte: vengono letti dall'offset 5 e 6 (con ordine inverso)
    block4 = get_block(card_data, 4)
    # Nota: nel C originale viene fatto: (temp_ptr[6] << 8) | (temp_ptr[5])
    current_credit = (block4[6] << 8) | block4[5]
    # Dal blocco 5 (settore 1 successivo) si ottiene il credito precedente
    block5 = get_block(card_data, 5)
    previous_credit = (block5[6] << 8) | block5[5]
    
    output = "Microel Card\n"
    output += "UID:" + " ".join(f"{b:02X}" for b in uid) + "\n"
    output += f"Current Credit: {current_credit // 100}.{current_credit % 100:02d} E\n"
    output += f"Previous Credit: {previous_credit // 100}.{previous_credit % 100:02d} E\n"
    
    return output

def main():
    if len(sys.argv) != 2:
        print("Usage: python microel.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        if not microel_read(card_data):
            print("Errore: lettura della carta fallita")
            return
        result = microel_parse(card_data)
        print(result)
    except Exception as e:
        print("Errore:", e)

if __name__ == '__main__':
    main()
