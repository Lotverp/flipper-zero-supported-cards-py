#!/usr/bin/env python3
import sys

def parse_csc_card(card_data: bytes) -> str:
    """
    Parser per la CSC Service Works Reloadable Cash Card.
    
    Si assume che:
      - card_data contenga il dump completo della carta (per una 1K, 1024 byte, 64 blocchi da 16 byte)
      - I blocchi sono indicizzati da 0 a 63.
    
    I blocchi e gli offset usati sono:
      - Blocco di ricarica (refill): blocco 2
         * refilled_balance: offset 9, lunghezza 2 byte (little endian)
         * refill_times: offset 5, lunghezza 2 byte
         * Inoltre, l’intero blocco viene usato per il calcolo del checksum (XOR su 16 byte)
      - Blocco del saldo corrente: blocco 4 (e copia di backup in blocco 8)
         * current_balance: 2 byte (primi 2 byte, little endian) usati per il saldo
         * I primi 4 byte di questi blocchi (saldo e “times”) devono essere uguali
      - Blocco "card lives": blocco 9, primi 2 byte
      - Blocco della firma di ricarica: blocco 13, primi 8 byte
      - UID della carta: in questo esempio, si assume che sia contenuto nei primi 4 byte del blocco 0
    """
    # Funzione helper per ottenere il blocco n (ogni blocco è 16 byte)
    def get_block(block_num: int) -> bytes:
        start = block_num * 16
        return card_data[start:start+16]
    
    # Verifica lunghezza minima: per una carta 1K ci aspettiamo almeno 1024 byte
    if len(card_data) < 1024:
        return "Errore: dati della carta troppo brevi (non una 1K?)"
    
    # Definizione dei blocchi usati (come nella versione C)
    refill_block_num = 2
    current_balance_block_num = 4
    current_balance_copy_block_num = 8
    card_lives_block_num = 9
    refill_sign_block_num = 13

    # Legge i blocchi del saldo corrente e della copia
    current_balance_block = get_block(current_balance_block_num)
    current_balance_copy_block = get_block(current_balance_copy_block_num)
    
    # Legge i primi 4 byte dei blocchi in little endian
    current_balance_and_times = int.from_bytes(current_balance_block[:4], byteorder='little')
    current_balance_and_times_copy = int.from_bytes(current_balance_copy_block[:4], byteorder='little')
    
    if current_balance_and_times != current_balance_and_times_copy:
        return "Errore: verifica backup fallita (saldo diverso dalla copia)"
    
    if current_balance_and_times == 0:
        return "Errore: i byte dei valori sono vuoti"
    
    # Dal blocco di ricarica (refill) estraiamo:
    refill_block = get_block(refill_block_num)
    # Il saldo ricaricato (refilled_balance) si trova a offset 9, lunghezza 2 byte
    refilled_balance = int.from_bytes(refill_block[9:9+2], byteorder='little')
    refilled_balance_dollar = refilled_balance // 100
    refilled_balance_cent = refilled_balance % 100
    
    # Saldo corrente: si usano i primi 2 byte del blocco corrente
    current_balance = int.from_bytes(current_balance_block[:2], byteorder='little')
    current_balance_dollar = current_balance // 100
    current_balance_cent = current_balance % 100
    
    # Numero di "lives" della carta (quante usi rimangono), da blocco 9, 2 byte
    card_lives_block = get_block(card_lives_block_num)
    card_lives = int.from_bytes(card_lives_block[:2], byteorder='little')
    
    # Numero di ricariche (refill_times) da blocco di ricarica, offset 5, 2 byte
    refill_times = int.from_bytes(refill_block[5:5+2], byteorder='little')
    
    # Firma di ricarica: blocco 13, 8 byte in little endian
    refill_sign_block = get_block(refill_sign_block_num)
    refill_sign = int.from_bytes(refill_sign_block[:8], byteorder='little')
    
    # Otteniamo l'UID della carta: in questo esempio, assumiamo che sia nel blocco 0 (primi 4 byte)
    uid_block = get_block(0)
    card_uid = int.from_bytes(uid_block[:4], byteorder='little')
    
    # Calcolo del checksum: XOR di tutti i 16 byte del blocco di ricarica (blocco 2)
    xor_result = 0
    for b in refill_block:
        xor_result ^= b
    
    # Se la firma di ricarica è 0 e refill_times è 1, allora la carta è nuova
    if refill_sign == 0 and refill_times == 1:
        output = (
            f"CSC Service Works\n"
            f"UID: {card_uid}\n"
            f"New Card\n"
            f"Card Value: {refilled_balance_dollar}.{refilled_balance_cent:02d} USD\n"
            f"Card Usages Left: {card_lives}"
        )
    else:
        if xor_result != 0:
            return "Errore: Checksum fallito"
        output = (
            f"CSC Service Works\n"
            f"UID: {card_uid}\n"
            f"Balance: {current_balance_dollar}.{current_balance_cent:02d} USD\n"
            f"Last Top-up: {refilled_balance_dollar}.{refilled_balance_cent:02d} USD\n"
            f"Top-up Count: {refill_times}\n"
            f"Card Usages Left: {card_lives}"
        )
    
    return output

# Esempio di utilizzo:
if __name__ == '__main__':
    # Assumiamo di avere un file binario con il dump della carta (es. "csc_dump.bin")
    try:
        with open("csc_dump.bin", "rb") as f:
            card_data = f.read()
        result = parse_csc_card(card_data)
        print(result)
    except FileNotFoundError:
        print("Errore: file dump della carta non trovato. Verifica il nome del file.")
