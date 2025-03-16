#!/usr/bin/env python3
import sys
import struct
from datetime import datetime

# Costanti
BLOCK_SIZE = 16
# Per una Mifare Classic 1K si hanno 64 blocchi.
TOTAL_BLOCKS = 64

# Settori usati
INFO_SECTOR = 15
TRIP_SECTOR = 4
PURSE_SECTOR = 6

# Signature attesa per il settore INFO (24 byte totali, i primi 16 nel primo blocco e i successivi 8 nel blocco seguente)
INFO_SECTOR_SIGNATURE = bytes([
    0xE2, 0x87, 0x80, 0x8E, 0x20, 0x87, 0xAE, 0xAB, 0xAE, 0xF2, 0xA0, 0xEF, 0x20, 0x8A,
    0xAE, 0xE0, 0xAE, 0xAD, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
])

# Funzioni di utilità

def get_block(data: bytes, block_num: int) -> bytes:
    """Restituisce il blocco (16 byte) identificato da block_num."""
    start = block_num * BLOCK_SIZE
    return data[start:start+BLOCK_SIZE]

def bytes_to_int_be(b: bytes) -> int:
    """Converte una sequenza di byte (big-endian) in intero."""
    return int.from_bytes(b, byteorder='big')

def bytes_to_int_le(b: bytes) -> int:
    """Converte una sequenza di byte (little-endian) in intero."""
    return int.from_bytes(b, byteorder='little')

def bcd_to_int(b: bytes) -> int:
    """
    Converte una sequenza di byte in formato BCD in un intero.
    Ogni nibble rappresenta una cifra decimale.
    """
    result = 0
    for byte in b:
        high = (byte >> 4) & 0x0F
        low = byte & 0x0F
        result = result * 100 + high * 10 + low
    return result

def mf_classic_first_block_of_sector(sector: int) -> int:
    """Per una carta Mifare Classic 1K, ogni settore ha 4 blocchi."""
    return sector * 4

def format_date(dt: datetime, separator: str = ".") -> str:
    """Formatta una data nel formato DD{sep}MM{sep}YYYY."""
    return dt.strftime(f"%d{separator}%m{separator}%Y")

def format_time(dt: datetime) -> str:
    """Formatta l'orario nel formato HH:MM."""
    return dt.strftime("%H:%M")

# Simulazione della conversione di un timestamp in datetime.
# Assumiamo che i timestamp siano in secondi dal'Unix epoch.
def timestamp_to_datetime(ts: int) -> datetime:
    return datetime.fromtimestamp(ts)

# Parser principale
def zolotaya_korona_parse(dump: bytes) -> str:
    # Controlla che il dump sia sufficientemente lungo
    if len(dump) < TOTAL_BLOCKS * BLOCK_SIZE:
        return "Errore: dump troppo corto."

    # INFO SECTOR: Il settore 15
    info_sector_start = mf_classic_first_block_of_sector(INFO_SECTOR)
    # Prendi il primo blocco del settore INFO
    block0 = get_block(dump, info_sector_start)
    # I primi 16 byte devono corrispondere ai primi 16 byte della signature
    if block0 != INFO_SECTOR_SIGNATURE[:16]:
        return "Errore: signature info settore non verificata (primo blocco)."
    # Prendi il blocco successivo (blocco 1 del settore INFO)
    block1 = get_block(dump, info_sector_start + 1)
    # I successivi 8 byte della signature (dalla posizione 16 alla fine) devono corrispondere
    if block1[:8] != INFO_SECTOR_SIGNATURE[16:]:
        return "Errore: signature info settore non verificata (secondo blocco)."

    # Se la signature è verificata, prosegui con il parsing.
    # INFO SECTOR - blocco 1:
    # Region number: BCD da 1 byte a partire dal byte 10 del blocco0 (del settore INFO)
    region_number = bcd_to_int(block0[10:11])

    # INFO SECTOR - blocco 2: (blocco 2 del settore INFO, cioè info_sector_start+2)
    block2 = get_block(dump, info_sector_start + 2)
    # A partire dal byte 4 del blocco2, leggi 2 byte in BCD per il card number prefix
    card_number_prefix = bcd_to_int(block2[4:6])
    # Leggi 8 byte in BCD per il card number postfix e dividili per 10
    card_number_postfix = bcd_to_int(block2[6:14]) // 10

    # TRIP SECTOR: Settore 4
    trip_sector_start = mf_classic_first_block_of_sector(4)
    # Blocco 0 del settore TRIP: a partire dal byte 7
    trip_block0 = get_block(dump, trip_sector_start)
    status = trip_block0[7] % 16
    sequence_number = bytes_to_int_be(trip_block0[8:10])
    discount_code = bytes_to_int_be(trip_block0[10:11])

    # Blocco 1 del settore TRIP: refill block, a partire dal byte 1
    trip_block1 = get_block(dump, trip_sector_start + 1)
    refill_block = trip_block1[1:]  # partendo dal byte 1
    refill_machine_id = bytes_to_int_le(refill_block[0:2])
    last_refill_timestamp = bytes_to_int_le(refill_block[2:6])
    last_refill_amount = bytes_to_int_le(refill_block[6:10])
    last_refill_amount_rub = last_refill_amount // 100
    last_refill_amount_kop = last_refill_amount % 100
    refill_counter = bytes_to_int_le(refill_block[10:12])
    last_refill_dt = timestamp_to_datetime(last_refill_timestamp)

    # Blocco 2 del settore TRIP: trip block
    trip_block2 = get_block(dump, trip_sector_start + 2)
    # Validator first letter: 1 byte (little-endian, ma basta l'intero) a partire dal byte 1
    validator_first_letter = chr(bytes_to_int_le(trip_block2[1:2]) & 0xFF)
    # Validator id: 3 byte in BCD a partire dal byte 2
    validator_id = bcd_to_int(trip_block2[2:5])
    last_trip_timestamp = bytes_to_int_le(trip_block2[6:10])
    track_number = bytes_to_int_le(trip_block2[10:11])
    prev_balance = bytes_to_int_le(trip_block2[11:15])
    prev_balance_rub = prev_balance // 100
    prev_balance_kop = prev_balance % 100
    last_trip_dt = timestamp_to_datetime(last_trip_timestamp)

    # PURSE SECTOR: Settore 6
    purse_sector_start = mf_classic_first_block_of_sector(PURSE_SECTOR)
    purse_block0 = get_block(dump, purse_sector_start)
    balance_val = bytes_to_int_le(purse_block0[0:4])
    balance_rub = balance_val // 100
    balance_kop = balance_val % 100

    # Per la formattazione delle date, assumiamo il formato DMY con separatore "."
    separator = "."

    expiry_date_str = format_date(last_refill_dt, separator)  # utilizziamo last_refill_dt come esempio
    last_trip_date_str = format_date(last_trip_dt, separator)
    last_refill_time_str = last_refill_dt.strftime("%H:%M")
    last_trip_time_str = last_trip_dt.strftime("%H:%M")

    # Costruzione dell’output:
    # Il numero della carta è composto da card_number_prefix e card_number_postfix.
    output = []
    output.append("Zolotaya korona")
    output.append(f"Card number: {card_number_prefix}{card_number_postfix:015d}")
    output.append(f"Region: {region_number}")
    output.append(f"Balance: {balance_rub}.{balance_kop:02d} RUR")
    output.append(f"Prev. balance: {prev_balance_rub}.{prev_balance_kop:02d} RUR")
    output.append(f"Last refill amount: {last_refill_amount_rub}.{last_refill_amount_kop:02d} RUR")
    output.append(f"Refill counter: {refill_counter}")
    output.append(f"Last refill: {expiry_date_str} at {last_refill_time_str}")
    output.append(f"Refill machine id: {refill_machine_id}")
    output.append(f"Last trip: {last_trip_date_str} at {last_trip_time_str}")
    output.append(f"Track number: {track_number}")
    output.append(f"Validator: {validator_first_letter}{validator_id:06d}")
    # Se fosse abilitato il flag debug (qui assumiamo False) si stamperebbero anche status, sequence_number, discount_code.
    return "\n".join(output)

def main():
    if len(sys.argv) != 2:
        print("Usage: python zolotaya_korona.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            dump = f.read()
        # Assumiamo che il dump contenga almeno 64 blocchi da 16 byte
        if len(dump) < TOTAL_BLOCKS * BLOCK_SIZE:
            print("Error: dump too short.")
            sys.exit(1)
        result = zolotaya_korona_parse(dump)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
