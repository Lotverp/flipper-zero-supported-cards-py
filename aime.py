#!/usr/bin/env python3

import logging
from typing import List, Optional

# Configurazione del logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("Aime")

# Costanti
AIME_KEY = 0x574343467632  # Chiave Aime in esadecimale
TAG = "Aime"

# Funzioni di utilità per la manipolazione dei bit
def num_to_bytes_be(num: int, size: int) -> bytes:
    return num.to_bytes(size, byteorder='big')

def bytes_to_num_be(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big')

# Simulazione dei dati della carta come lista di blocchi (ogni blocco è 16 byte)
class CardData:
    def __init__(self, blocks: List[bytes]):
        self.blocks = blocks  # Lista di bytearray o bytes, ogni elemento è un blocco di 16 byte

    def get_sector_trailer(self, sector: int) -> bytes:
        # Il trailer del settore è l'ultimo blocco del settore (blocco 3, 7, 11, ecc.)
        block_num = (sector * 4) + 3
        return self.blocks[block_num] if block_num < len(self.blocks) else b'\x00' * 16

    def get_block(self, block_num: int) -> bytes:
        return self.blocks[block_num] if block_num < len(self.blocks) else b'\x00' * 16

# Funzione per verificare se è una carta Aime
def aime_verify(card_data: CardData) -> bool:
    try:
        # Verifica la chiave nel settore 0 (trailer del settore)
        sec_trailer = card_data.get_sector_trailer(0)
        key_a = bytes_to_num_be(sec_trailer[:6])  # Primi 6 byte sono Key A
        if key_a != AIME_KEY:
            logger.debug(f"Chiave non valida: {key_a:012x}, attesa: {AIME_KEY:012x}")
            return False

        # Verifica il magic number nel blocco 1
        block_1 = card_data.get_block(1)
        aime_magic = block_1[:4]
        if aime_magic != b'SBSD':
            logger.debug(f"Magic number non valido: {aime_magic}")
            return False

        logger.debug("Carta Aime verificata con successo")
        return True
    except Exception as e:
        logger.debug(f"Errore nella verifica: {e}")
        return False

# Funzione per estrapolare i dati dalla carta Aime
def aime_parse(card_data: CardData) -> Optional[dict]:
    try:
        # Verifica preliminare
        if not aime_verify(card_data):
            return None

        # Estrai i dati
        block_1 = card_data.get_block(1)
        block_2 = card_data.get_block(2)

        # Checksum (blocco 1, byte 13-15)
        checksum = block_1[13:16]

        # Access Code (blocco 2, byte 6-15)
        access_code = block_2[6:16]

        # Converti access code in stringa leggibile (formato decimale esadecimale)
        access_code_str = " ".join(
            f"{access_code[i]:02x}{access_code[i+1]:02x}"
            for i in range(0, 10, 2)
        )

        # Verifica che l'access code sia un numero decimale in formato esadecimale
        if not all(char in '0123456789 ' for char in access_code_str):
            logger.debug(f"Access code non valido: {access_code_str}")
            return None

        # Risultato
        result = {
            "access_code": access_code_str,
            "checksum": f"{checksum[0]:02X}{checksum[1]:02X}{checksum[2]:02X}"
        }
        logger.debug(f"Dati estratti: {result}")
        return result
    except Exception as e:
        logger.error(f"Errore durante il parsing: {e}")
        return None

# Esempio di utilizzo con dati simulati
if __name__ == "__main__":
    # Simulazione dei blocchi della carta (64 blocchi da 16 byte ciascuno)
    sample_blocks = [b'\x00' * 16 for _ in range(64)]
    
    # Settore 0, blocco 3 (trailer): Key A
    sample_blocks[3] = num_to_bytes_be(AIME_KEY, 6) + b'\x00' * 10
    # Blocco 1: Magic number e checksum
    sample_blocks[1] = b'SBSD' + b'\x00' * 9 + b'\x12\x34\x56'
    # Blocco 2: Access code
    sample_blocks[2] = b'\x00' * 6 + b'1234567890'

    # Crea l'oggetto CardData
    card = CardData(sample_blocks)

    # Verifica
    if aime_verify(card):
        logger.info("Carta identificata come Aime")

    # Estrai i dati
    parsed_data = aime_parse(card)
    if parsed_data:
        print("Aime Card")
        print(f"Access Code: {parsed_data['access_code']}")
        print(f"Checksum: {parsed_data['checksum']}")