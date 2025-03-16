#!/usr/bin/env python3

import logging
from typing import List, Optional

# Configurazione del logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("AllInOne")

# Costanti
TAG = "AllInOne"

# Tipi di layout come enumerazione
class AllInOneLayoutType:
    TYPE_A = "A"
    TYPE_D = "D"
    TYPE_2 = "2"
    TYPE_UNKNOWN = "Unknown"

# Simulazione dei dati della carta come lista di pagine (ogni pagina è 4 byte)
class CardData:
    def __init__(self, pages: List[bytes]):
        self.pages = pages  # Lista di bytearray o bytes, ogni elemento è una pagina di 4 byte

    def get_page(self, page_num: int) -> bytes:
        return self.pages[page_num] if page_num < len(self.pages) else b'\x00' * 4

# Funzione per determinare il tipo di layout
def all_in_one_get_layout(card_data: CardData) -> str:
    # Controlla la seconda metà del terzo byte della pagina 5
    layout_byte = card_data.get_page(5)[2]
    layout_half_byte = layout_byte & 0x0F

    logger.debug(f"Layout byte: {layout_byte:02x}")
    logger.debug(f"Layout half-byte: {layout_half_byte:02x}")

    if layout_half_byte == 0x0A:
        return AllInOneLayoutType.TYPE_A
    elif layout_half_byte == 0x0D:
        return AllInOneLayoutType.TYPE_D
    elif layout_half_byte == 0x02:
        return AllInOneLayoutType.TYPE_2
    else:
        logger.error(f"Tipo di layout sconosciuto: {layout_half_byte}")
        return AllInOneLayoutType.TYPE_UNKNOWN

# Funzione per verificare e parsare i dati della carta All-In-One
def all_in_one_parse(card_data: CardData) -> Optional[dict]:
    try:
        # Verifica iniziale: pagina 4 deve iniziare con 0x45 0xD9
        page_4 = card_data.get_page(4)
        if page_4[0] != 0x45 or page_4[1] != 0xD9:
            logger.error("Pass non verificato")
            return None

        # Determina il tipo di layout
        layout_type = all_in_one_get_layout(card_data)

        # Estrai il numero di corse rimanenti
        ride_count = 0
        if layout_type == AllInOneLayoutType.TYPE_A:
            ride_count = card_data.get_page(8)[0]  # Prima byte della pagina 8
        elif layout_type == AllInOneLayoutType.TYPE_D:
            ride_count = card_data.get_page(9)[1]  # Secondo byte della pagina 9
        else:
            logger.error(f"Layout sconosciuto: {layout_type}")
            ride_count = 137  # Valore di fallback

        # Estrai il numero seriale (32 bit)
        page_4_data = card_data.get_page(4)
        page_5_data = card_data.get_page(5)
        serial = (
            (page_4_data[2] & 0x0F) << 28 |  # Seconda metà del terzo byte della pagina 4
            page_4_data[3] << 20 |           # Quarto byte della pagina 4
            page_5_data[0] << 12 |           # Primo byte della pagina 5
            page_5_data[1] << 4 |            # Secondo byte della pagina 5
            (page_5_data[2] >> 4)            # Prima metà del terzo byte della pagina 5
        )

        # Risultato
        result = {
            "number": serial,
            "rides_left": ride_count,
            "layout_type": layout_type
        }
        logger.debug(f"Dati estratti: {result}")
        return result
    except Exception as e:
        logger.error(f"Errore durante il parsing: {e}")
        return None

# Esempio di utilizzo con dati simulati
if __name__ == "__main__":
    # Simulazione dei dati della carta (almeno 10 pagine da 4 byte ciascuna)
    sample_pages = [b'\x00' * 4 for _ in range(16)]
    
    # Pagina 4: verifica e parte del seriale
    sample_pages[4] = b'\x45\xD9\xB8\x17'  # 45 D9 B8 17
    # Pagina 5: parte del seriale e layout
    sample_pages[5] = b'\xA2\xA4\x2A' + b'\x00'  # Layout A (0x0A)
    # Pagina 8: numero di corse per layout A
    sample_pages[8] = b'\x05' + b'\x00' * 3  # 5 corse rimanenti
    # Pagina 9: numero di corse per layout D (non usato in questo esempio)
    sample_pages[9] = b'\x00\x03' + b'\x00' * 2  # 3 corse rimanenti

    # Crea l'oggetto CardData
    card = CardData(sample_pages)

    # Verifica e parsing
    parsed_data = all_in_one_parse(card)
    if parsed_data:
        print("All-In-One Card")
        print(f"Number: {parsed_data['number']}")
        print(f"Rides left: {parsed_data['rides_left']}")
        print(f"Layout type: {parsed_data['layout_type']}")