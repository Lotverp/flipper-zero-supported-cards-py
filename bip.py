#!/usr/bin/env python3

import logging
from typing import List, Optional, Dict
from dataclasses import dataclass
from datetime import datetime

# Configurazione del logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("Bip")

# Costanti
TAG = "Bip"
BIP_CARD_ID_SECTOR_NUMBER = 0
BIP_BALANCE_SECTOR_NUMBER = 8
BIP_TRIP_TIME_WINDOW_SECTOR_NUMBER = 5
BIP_LAST_TOP_UPS_SECTOR_NUMBER = 10
BIP_TRIPS_INFO_SECTOR_NUMBER = 11

# Chiavi predefinite per i settori (simulazione per MIFARE Classic 1K)
BIP_1K_KEYS = [
    {"a": 0x3a42f33af429, "b": 0x1fc235ac1309},
    {"a": 0x6338a371c0ed, "b": 0x243f160918d1},
    {"a": 0xf124c2578ad0, "b": 0x9afc42372af1},
    {"a": 0x32ac3b90ac13, "b": 0x682d401abb09},
    {"a": 0x4ad1e273eaf1, "b": 0x067db45454a9},
    {"a": 0xe2c42591368a, "b": 0x15fc4c7613fe},
    {"a": 0x2a3c347a1200, "b": 0x68d30288910a},
    {"a": 0x16f3d5ab1139, "b": 0xf59a36a2546d},
    {"a": 0x937a4fff3011, "b": 0x64e3c10394c2},
    {"a": 0x35c3d2caee88, "b": 0xb736412614af},
    {"a": 0x693143f10368, "b": 0x324f5df65310},
    {"a": 0xa3f97428dd01, "b": 0x643fb6de2217},
    {"a": 0x63f17a449af0, "b": 0x82f435dedf01},
    {"a": 0xc4652c54261c, "b": 0x0263de1278f3},
    {"a": 0xd49e2826664f, "b": 0x51284c3686a6},
    {"a": 0x3df14c8000a1, "b": 0x6a470d54127c},
]

# Struttura per rappresentare una transazione
@dataclass
class BipTransaction:
    datetime: datetime
    amount: int

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

# Funzioni di utilità per la manipolazione dei bit
def bytes_to_num_le(data: bytes) -> int:
    return int.from_bytes(data, byteorder='little')

def bytes_to_num_be(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big')

# Funzione per parsare una data da un blocco
def bip_parse_datetime(block: bytes) -> datetime:
    word_0 = bytes_to_num_le(block[0:2])
    word_1 = bytes_to_num_le(block[1:3])
    word_2 = bytes_to_num_le(block[2:4])
    word_3 = bytes_to_num_le(block[3:5])

    day = (word_0 >> 6) & 0x1F
    month = (word_0 >> 11) & 0x0F
    year = 2000 + ((word_1 >> 7) & 0x1F)
    hour = (word_2 >> 4) & 0x1F
    minute = (word_2 >> 9) & 0x3F
    second = (word_3 >> 7) & 0x3F

    return datetime(year, month, day, hour, minute, second)

# Funzione per verificare se un blocco è vuoto
def is_bip_block_empty(block: bytes) -> bool:
    return all(byte == 0 for byte in block[:-1])  # Esclude l'ultimo byte (checksum)

# Funzione per verificare se è una carta Bip!
def bip_verify(card_data: CardData) -> bool:
    try:
        # Verifica la chiave del settore 0
        sec_trailer = card_data.get_sector_trailer(0)
        key_a = bytes_to_num_be(sec_trailer[:6])
        key_b = bytes_to_num_be(sec_trailer[10:16])

        if key_a != BIP_1K_KEYS[0]["a"] or key_b != BIP_1K_KEYS[0]["b"]:
            logger.debug(f"Chiavi non valide: Key A={key_a:012x}, Key B={key_b:012x}")
            return False

        logger.debug("Carta Bip! verificata con successo")
        return True
    except Exception as e:
        logger.debug(f"Errore nella verifica: {e}")
        return False

# Funzione per estrapolare i dati dalla carta Bip!
def bip_parse(card_data: CardData) -> Optional[Dict]:
    try:
        # Verifica preliminare
        if not bip_verify(card_data):
            return None

        result = {
            "card_id": 0,
            "balance": 0,
            "flags": 0,
            "trip_time_window": None,
            "top_ups": [None] * 3,
            "charges": [None] * 3
        }

        # Card ID (settore 0, blocco 1, byte 4-7, little-endian)
        block_num = BIP_CARD_ID_SECTOR_NUMBER * 4 + 1
        block = card_data.get_block(block_num)
        result["card_id"] = bytes_to_num_le(block[4:8])

        # Balance (settore 8, blocco 1, byte 0-1, little-endian)
        block_num = BIP_BALANCE_SECTOR_NUMBER * 4 + 1
        block = card_data.get_block(block_num)
        result["balance"] = bytes_to_num_le(block[0:2])

        # Flags (settore 8, blocco 1, byte 2-3, little-endian)
        result["flags"] = bytes_to_num_le(block[2:4])

        # Trip Time Window (settore 5, blocco 1, byte 0-7)
        block_num = BIP_TRIP_TIME_WINDOW_SECTOR_NUMBER * 4 + 1
        block = card_data.get_block(block_num)
        result["trip_time_window"] = bip_parse_datetime(block)

        # Ultimi 3 top-ups (settore 10, blocchi 0-2)
        block_start = BIP_LAST_TOP_UPS_SECTOR_NUMBER * 4
        for i in range(3):
            block = card_data.get_block(block_start + i)
            if not is_bip_block_empty(block):
                dt = bip_parse_datetime(block)
                amount = bytes_to_num_le(block[9:11]) >> 2
                result["top_ups"][i] = BipTransaction(datetime=dt, amount=amount)

        # Ultimi 3 charges (settore 11, blocchi 0-2)
        block_start = BIP_TRIPS_INFO_SECTOR_NUMBER * 4
        for i in range(3):
            block = card_data.get_block(block_start + i)
            if not is_bip_block_empty(block):
                dt = bip_parse_datetime(block)
                amount = bytes_to_num_le(block[10:12]) >> 2
                result["charges"][i] = BipTransaction(datetime=dt, amount=amount)

        # Ordina top-ups e charges per data (più recente prima)
        result["top_ups"] = sorted(
            [t for t in result["top_ups"] if t], key=lambda x: x.datetime, reverse=True
        )
        result["charges"] = sorted(
            [c for c in result["charges"] if c], key=lambda x: x.datetime, reverse=True
        )

        logger.debug(f"Dati estratti: {result}")
        return result
    except Exception as e:
        logger.error(f"Errore durante il parsing: {e}")
        return None

# Esempio di utilizzo con dati simulati
if __name__ == "__main__":
    # Simulazione dei blocchi della carta (64 blocchi da 16 byte)
    sample_blocks = [b'\x00' * 16 for _ in range(64)]

    # Settore 0, blocco 3 (trailer): Key A e Key B
    sample_blocks[3] = (
        bytes.fromhex("3a42f33af429") + b'\x00\x00\x00\x00' + bytes.fromhex("1fc235ac1309")
    )
    # Settore 0, blocco 1: Card ID
    sample_blocks[1] = b'\x00' * 4 + bytes.fromhex("12345678") + b'\x00' * 4
    # Settore 8, blocco 1: Balance e Flags
    sample_blocks[33] = bytes.fromhex("e8030200") + b'\x00' * 12  # 1000 e flags 2
    # Settore 5, blocco 1: Trip Time Window (es. 2023-10-15 14:30:00)
    sample_blocks[21] = bytes.fromhex("604f172e") + b'\x00' * 12
    # Settore 10, blocco 0: Top-up (es. 2023-10-10 10:00:00, 500)
    sample_blocks[40] = bytes.fromhex("404b132c1400") + b'\x00' * 10
    # Settore 11, blocco 0: Charge (es. 2023-10-11 12:00:00, 100)
    sample_blocks[44] = bytes.fromhex("c04c132c1800") + b'\x00' * 10

    # Crea l'oggetto CardData
    card = CardData(sample_blocks)

    # Verifica
    if bip_verify(card):
        logger.info("Carta identificata come Tarjeta Bip!")

    # Estrai i dati
    parsed_data = bip_parse(card)
    if parsed_data:
        print("Tarjeta Bip!")
        print(f"Card Number: {parsed_data['card_id']}")
        print(f"Balance: ${parsed_data['balance']} (flags {parsed_data['flags']})")
        print("Current Trip Window Ends:")
        print(f"  @ {parsed_data['trip_time_window'].strftime('%Y-%m-%d %H:%M:%S')}")
        print("Last Top-ups:")
        for top_up in parsed_data['top_ups']:
            if top_up:
                print(f"+${top_up.amount}")
                print(f"  @ {top_up.datetime.strftime('%Y-%m-%d %H:%M:%S')}")
        print("Last Charges (Trips):")
        for charge in parsed_data['charges']:
            if charge:
                print(f"-${charge.amount}")
                print(f"  @ {charge.datetime.strftime('%Y-%m-%d %H:%M:%S')}")