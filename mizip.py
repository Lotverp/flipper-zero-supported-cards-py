#!/usr/bin/env python3
import sys

# Costanti
KEY_LENGTH = 6
MIZIP_KEY_TO_GEN = 5
UID_LENGTH = 4
MF_CLASSIC_BLOCK_SIZE = 16
EXPECTED_DUMP_SIZE = 1024

# Definizione delle chiavi predefinite per le MiZIP card
mizip_1k_keys = [
    {"a": 0xa0a1a2a3a4a5, "b": 0xb4c132439eef},  # Settore 0
    {"a": 0x000000000000, "b": 0x000000000000},  # Settore 1
    {"a": 0x000000000000, "b": 0x000000000000},  # Settore 2
    {"a": 0x000000000000, "b": 0x000000000000},  # Settore 3
    {"a": 0x000000000000, "b": 0x000000000000},  # Settore 4
    {"a": 0x0222179AB995, "b": 0x13321774F9B5},  # Settore 5
    {"a": 0xB25CBD76A7B4, "b": 0x7571359B4274},  # Settore 6
    {"a": 0xDA857B4907CC, "b": 0xD26B856175F7},  # Settore 7
    {"a": 0x16D85830C443, "b": 0x8F790871A21E},  # Settore 8
    {"a": 0x88BD5098FC82, "b": 0xFCD0D77745E4},  # Settore 9
    {"a": 0x983349449D78, "b": 0xEA2631FBDEDD},  # Settore 10
    {"a": 0xC599F962F3D9, "b": 0x949B70C14845},  # Settore 11
    {"a": 0x72E668846BE8, "b": 0x45490B5AD707},  # Settore 12
    {"a": 0xBCA105E5685E, "b": 0x248DAF9D674D},  # Settore 13
    {"a": 0x4F6FE072D1FD, "b": 0x4250A05575FA},  # Settore 14
    {"a": 0x56438ABE8152, "b": 0x59A45912B311},  # Settore 15
]

mizip_mini_keys = [
    {"a": 0xa0a1a2a3a4a5, "b": 0xb4c132439eef},  # Settore 0
    {"a": 0x000000000000, "b": 0x000000000000},  # Settore 1
    {"a": 0x000000000000, "b": 0x000000000000},  # Settore 2
    {"a": 0x000000000000, "b": 0x000000000000},  # Settore 3
    {"a": 0x000000000000, "b": 0x000000000000},  # Settore 4
]

# Configurazione della carta MiZIP
# La struttura di configurazione conterrà il settore da verificare e il puntatore alle chiavi
def mizip_get_card_config(card_type: str):
    config = {}
    if card_type.lower() == "1k":
        config['verify_sector'] = 0
        config['keys'] = mizip_1k_keys
    elif card_type.lower() == "mini":
        config['verify_sector'] = 0
        config['keys'] = mizip_mini_keys
    else:
        return None
    return config

# KDF per MiZIP
def mizip_generate_key(uid: bytes):
    # Tabelle XOR per la generazione di Key A e Key B
    xor_table_keyA = [
        [0x09, 0x12, 0x5A, 0x25, 0x89, 0xE5],
        [0xAB, 0x75, 0xC9, 0x37, 0x92, 0x2F],
        [0xE2, 0x72, 0x41, 0xAF, 0x2C, 0x09],
        [0x31, 0x7A, 0xB7, 0x2F, 0x44, 0x90]
    ]
    xor_table_keyB = [
        [0xF1, 0x2C, 0x84, 0x53, 0xD8, 0x21],
        [0x73, 0xE7, 0x99, 0xFE, 0x32, 0x41],
        [0xAA, 0x4D, 0x13, 0x76, 0x56, 0xAE],
        [0xB0, 0x13, 0x27, 0x27, 0x2D, 0xFD]
    ]
    # Tabelle di permutazione
    xorOrderA = [0, 1, 2, 3, 0, 1]
    xorOrderB = [2, 3, 0, 1, 2, 3]

    # Creiamo due liste per le chiavi generate (5 elementi ciascuna)
    keyA = [bytes(KEY_LENGTH) for _ in range(MIZIP_KEY_TO_GEN)]
    keyB = [bytes(KEY_LENGTH) for _ in range(MIZIP_KEY_TO_GEN)]
    # Genera le chiavi per j = 1,2,3,4 (indice 1 a 4)
    # Lasciamo l'indice 0 invariato
    keyA = list(keyA)
    keyB = list(keyB)
    for j in range(1, MIZIP_KEY_TO_GEN):
        tempA = []
        tempB = []
        for i in range(KEY_LENGTH):
            tempA.append(uid[xorOrderA[i]] ^ xor_table_keyA[j - 1][i])
            tempB.append(uid[xorOrderB[i]] ^ xor_table_keyB[j - 1][i])
        keyA[j] = bytes(tempA)
        keyB[j] = bytes(tempB)
    return keyA, keyB

# Funzione helper per estrarre un blocco dal dump
def get_block(card_data: bytes, block_num: int) -> bytes:
    start = block_num * MF_CLASSIC_BLOCK_SIZE
    return card_data[start:start+MF_CLASSIC_BLOCK_SIZE]

# Funzione di verifica: prova ad autenticare il settore di verifica con la chiave B
def mizip_verify_type(nfc, card_data: bytes, card_type: str) -> bool:
    config = mizip_get_card_config(card_type)
    if config is None:
        return False
    verify_sector = config['verify_sector']
    # Il blocco di verifica è il primo blocco del settore (settore*4)
    block_num = verify_sector * 4
    # Utilizza la chiave B predefinita del settore di verifica
    expected_keyB = config['keys'][verify_sector]['b']
    # Simuliamo l'autenticazione confrontando il valore memorizzato nel trailer del settore
    trailer_block = get_block(card_data, verify_sector * 4 + 3)
    stored_keyB = int.from_bytes(trailer_block[6:12], 'big')
    return stored_keyB == expected_keyB

def mizip_verify(card_data: bytes) -> bool:
    # Proviamo sia per una carta 1K che per una Mini
    return mizip_verify_type(None, card_data, "1K") or mizip_verify_type(None, card_data, "mini")

# Funzione di lettura: genera le chiavi a partire dall'UID e aggiorna la configurazione
def mizip_read(card_data: bytes) -> bool:
    if len(card_data) < EXPECTED_DUMP_SIZE:
        return False
    # Estrae l'UID (i primi 4 byte del dump)
    uid = card_data[0:UID_LENGTH]
    if len(uid) != UID_LENGTH:
        return False
    keyA_gen, keyB_gen = mizip_generate_key(uid)
    # Otteniamo la configurazione in base al tipo; per questa conversione ipotizziamo una carta Mini
    config = mizip_get_card_config("mini")
    if config is None:
        return False
    total_sectors = 16  # Per una 1K
    # Aggiorna le chiavi per i settori che sono a zero
    for i in range(total_sectors):
        if config['keys'][i]['a'] == 0:
            config['keys'][i]['a'] = int.from_bytes(keyA_gen[i], 'big')
        if config['keys'][i]['b'] == 0:
            config['keys'][i]['b'] = int.from_bytes(keyB_gen[i], 'big')
    # In questa simulazione consideriamo la lettura riuscita
    return True

# Funzione di parsing: verifica la chiave e poi estrae l'UID e il credito
def mizip_parse(card_data: bytes) -> str:
    if len(card_data) < EXPECTED_DUMP_SIZE:
        return "Error: Card dump too short."
    
    # Ottieni la configurazione (ipotizziamo carta Mini)
    config = mizip_get_card_config("mini")
    if config is None:
        return "Error: Unsupported card type."
    
    # Verifica la chiave nel trailer del settore di verifica (settore 0)
    trailer_block = get_block(card_data, config['verify_sector'] * 4 + 3)
    stored_key = int.from_bytes(trailer_block[6:12], 'big')
    expected_key = config['keys'][config['verify_sector']]['b']
    if stored_key != expected_key:
        return "Error: Key verification failed."
    
    # Estrae l'UID
    uid = card_data[0:UID_LENGTH]
    
    # Determina i puntatori per il credito
    credit_pointer = 0x08
    previous_credit_pointer = 0x09
    if card_data[10 * MF_CLASSIC_BLOCK_SIZE] == 0x55:
        credit_pointer = 0x09
        previous_credit_pointer = 0x08
    
    # Legge il credito corrente: 2 byte dal blocco indicato dal credit_pointer
    block_credit = get_block(card_data, credit_pointer)
    current_credit = (block_credit[2] << 8) | block_credit[1]
    # Legge il credito precedente
    block_prev = get_block(card_data, previous_credit_pointer)
    previous_credit = (block_prev[2] << 8) | block_prev[1]
    
    output = "MiZIP Card\n"
    output += "UID: " + " ".join(f"{b:02X}" for b in uid) + "\n"
    output += f"Current Credit: {current_credit // 100}.{current_credit % 100:02d} E\n"
    output += f"Previous Credit: {previous_credit // 100}.{previous_credit % 100:02d} E\n"
    return output

def main():
    if len(sys.argv) != 2:
        print("Usage: python mizip.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        result = mizip_parse(card_data)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
