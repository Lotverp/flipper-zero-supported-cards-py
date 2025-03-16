#!/usr/bin/env python3
import sys

MF_CLASSIC_BLOCK_SIZE = 16
# Definiamo il settore delle credenziali Gallagher.
# Per una Mifare Classic 1K, ogni settore ha 4 blocchi.
GALLAGHER_CREDENTIAL_SECTOR = 8
# Il blocco trailer delle credenziali inizia al blocco: settore * 4
CREDENTIAL_BLOCK_NUM = GALLAGHER_CREDENTIAL_SECTOR * 4  # blocco 32
# Il blocco successivo deve contenere il valore ASCII costante "GALLAGHER CARDAX"
GALLAGHER_CARDAX_ASCII = b"GALLAGHER CARDAX"  # esattamente 16 byte

class GallagherCredential:
    def __init__(self, region: int, facility: int, card: int, issue: int):
        self.region = region
        self.facility = facility
        self.card = card
        self.issue = issue

def get_block(card_data: bytes, block_num: int) -> bytes:
    """Restituisce il blocco 'block_num' (ogni blocco è di 16 byte)."""
    start = block_num * MF_CLASSIC_BLOCK_SIZE
    return card_data[start:start+MF_CLASSIC_BLOCK_SIZE]

def deobfuscate_and_parse_credential(cred_block: bytes) -> GallagherCredential:
    """
    Data la credenziale (primi 8 byte del blocco), estrae i campi:
      - region: nibble alto del primo byte (0-15)
      - facility: ((first_byte & 0x0F) << 8) | second_byte
      - card: 4 byte successivi (byte 2..5), big endian
      - issue: 2 byte successivi (byte 6..7), big endian
    """
    if len(cred_block) < 8:
        raise ValueError("Credential block too short")
    # Prendiamo i primi 8 byte (la parte effettiva)
    cred = cred_block[:8]
    region = (cred[0] >> 4) & 0x0F
    facility = ((cred[0] & 0x0F) << 8) | cred[1]
    card = int.from_bytes(cred[2:6], byteorder='big')
    issue = int.from_bytes(cred[6:8], byteorder='big')
    return GallagherCredential(region, facility, card, issue)

def parse_gallagher_card(card_data: bytes) -> str:
    """
    Parser per Gallagher access control cards (New Zealand).
    Verifica che:
      1. I primi 16 byte del blocco credenziali contengano 8 byte e il loro inverso bit a bit.
      2. Il blocco successivo (blocco 33) corrisponda a GALLAGHER_CARDAX_ASCII.
    Quindi deobfusca e interpreta la credential.
    """
    # Controlla che il dump sia sufficientemente lungo.
    if len(card_data) < (CREDENTIAL_BLOCK_NUM + 2) * MF_CLASSIC_BLOCK_SIZE:
        return "Errore: dump della carta troppo corto."
    
    # Legge il blocco delle credenziali (blocco 32)
    credential_block = get_block(card_data, CREDENTIAL_BLOCK_NUM)
    if len(credential_block) < 16:
        return "Errore: blocco credenziali incompleto."
    
    # Verifica: i primi 8 byte devono essere l'inverso bit a bit dei successivi 8 byte.
    first_half = int.from_bytes(credential_block[:8], byteorder='big')
    second_half = int.from_bytes(credential_block[8:], byteorder='big')
    if first_half != (~second_half & ((1 << 64) - 1)):
        return "Errore: credenziali non valide (inversione non corretta)."
    
    # Legge il blocco successivo (blocco 33) e verifica che corrisponda al valore costante.
    cardax_block = get_block(card_data, CREDENTIAL_BLOCK_NUM + 1)
    if cardax_block != GALLAGHER_CARDAX_ASCII:
        return "Errore: blocco CARDAX non corrispondente."
    
    # Deobfusca ed estrae la credential.
    credential = deobfuscate_and_parse_credential(credential_block)
    
    # Calcola il carattere di display per la regione.
    if credential.region < 16:
        display_region = chr(ord('A') + credential.region)
    else:
        display_region = '?'
    
    # Format output
    output = (
        "Gallagher NZ\n"
        f"Facility {display_region}{credential.facility}\n"
        f"Card {credential.card} (IL {credential.issue})"
    )
    return output

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Uso: python gallagher.py <dump_file>")
        sys.exit(1)
    
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        result = parse_gallagher_card(card_data)
        print(result)
    except Exception as e:
        print("Errore:", e)
