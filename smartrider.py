#!/usr/bin/env python3
import sys
import struct
from datetime import datetime, timedelta

# Costanti
MAX_TRIPS = 10
MAX_BLOCKS = 64

# Chiavi standard (3 chiavi da 6 byte ciascuna) per l'autenticazione
STANDARD_KEYS = [
    bytes([0x20, 0x31, 0xD1, 0xE5, 0x7A, 0x3B]),
    bytes([0x4C, 0xA6, 0x02, 0x9F, 0x94, 0x73]),
    bytes([0x19, 0x19, 0x53, 0x98, 0xE3, 0x2F])
]

# Funzione per leggere un blocco (16 byte) dal dump
def get_block(card_data: bytes, block_num: int) -> bytes:
    start = block_num * 16
    return card_data[start:start+16]

# Funzione per leggere un intero little-endian dai byte
def get_number_le(data: bytes, start: int, length: int) -> int:
    return int.from_bytes(data[start:start+length], byteorder='little')

# Funzione per leggere un intero big-endian dai byte
def get_number_be(data: bytes, start: int, length: int) -> int:
    return int.from_bytes(data[start:start+length], byteorder='big')

# Funzione per autenticare un settore e leggere un blocco
def authenticate_and_read(nfc_data: bytes, sector: int, key: bytes) -> bytes:
    # In questa conversione ipotizziamo che il dump sia già letto e le chiavi siano usate per
    # "verificare" che i primi 6 byte del trailer del settore corrispondano alla chiave attesa.
    # Il trailer del settore si trova nel blocco: (sector * 4 + 3)
    trailer = get_block(nfc_data, sector * 4 + 3)
    if trailer[0:6] != key:
        raise ValueError(f"Authentication failed for sector {sector}")
    # Restituisce il blocco letto (simulato)
    return trailer

# Funzione di verifica della SmartRider card
def smartrider_verify(nfc_data: bytes) -> bool:
    # Per ogni chiave (3 in totale), verifica che il blocco letto corrisponda alla chiave attesa.
    try:
        for i in range(3):
            sector = i * 6  # come nel C originale
            # Scegliamo la chiave A per i settori, per il settore 0 usiamo STANDARD_KEYS[0],
            # per gli altri STANDARD_KEYS[1] e STANDARD_KEYS[2] (per i settori > 0)
            key = STANDARD_KEYS[0] if i == 0 else STANDARD_KEYS[1] if i == 1 else STANDARD_KEYS[2]
            authenticate_and_read(nfc_data, sector, key)
        return True
    except Exception as e:
        return False

# Funzione per leggere la SmartRider card
def smartrider_read(nfc_data: bytes) -> bytes:
    # In questa conversione assumiamo che nfc_data contenga già il dump dei dati.
    # Se il dump non è sufficientemente lungo, solleviamo un'eccezione.
    if len(nfc_data) < MAX_BLOCKS * 16:
        raise ValueError("Dump too short")
    return nfc_data

# Struttura dati per un viaggio
class TripData:
    def __init__(self):
        self.timestamp = 0
        self.cost = 0
        self.transaction_number = 0
        self.journey_number = 0
        self.route = ""
        self.tap_on = False
        self.block = 0

# Struttura dati per SmartRider
class SmartRiderData:
    def __init__(self):
        self.balance = 0
        self.issued_days = 0
        self.expiry_days = 0
        self.purchase_cost = 0
        self.auto_load_threshold = 0
        self.auto_load_value = 0
        self.card_serial_number = ""
        self.token = 0
        self.trips = []
        self.trip_count = 0

# Funzione per parsare i dati di un viaggio da un blocco
def parse_trip_data(block_data: bytes, block_number: int) -> TripData:
    trip = TripData()
    # Il timestamp è a partire dal byte 3 (4 byte, little-endian)
    trip.timestamp = get_number_le(block_data, 3, 4)
    # Il flag tap_on è nel byte 7, bit 4 (0x10)
    trip.tap_on = (block_data[7] & 0x10) == 0x10
    # La route: 4 byte a partire dal byte 8, convertiti in ASCII
    trip.route = block_data[8:12].decode('ascii', errors='replace')
    # Il costo: 2 byte a partire dal byte 13 (little-endian)
    trip.cost = get_number_le(block_data, 13, 2)
    # Transaction number: 2 byte a partire dal byte 0
    trip.transaction_number = get_number_le(block_data, 0, 2)
    # Journey number: 2 byte a partire dal byte 2
    trip.journey_number = get_number_le(block_data, 2, 2)
    trip.block = block_number
    return trip

# Funzione per convertire un timestamp (in minuti) in una data formattata
def calculate_date(timestamp: int) -> str:
    # Aggiungiamo 24 ore (1440 minuti) come offset e partiamo dal 2010-01-01
    base = datetime(2010, 1, 1)
    dt = base + timedelta(minutes=timestamp + 1440)
    return dt.strftime("%d.%m.%Y %H:%M")

# Funzione per ottenere la concessione (concession type) dalla token
def get_concession_type(token: int) -> str:
    # Tabella di esempio, come nel C originale
    concession_types = [
        "Pre-issue", "Standard Fare", "Student", None, "Tertiary", None,
        "Seniors", "Health Care", None, None, None, None, None, None,
        "PTA Staff", "Pensioner", "Free Travel"
    ]
    if 0 <= token < len(concession_types) and concession_types[token]:
        return concession_types[token]
    return "Unknown"

# Funzione per parsare il dump SmartRider
def smartrider_parse(nfc_data: bytes) -> str:
    # In questa conversione, utilizziamo la struttura SmartRiderData per accumulare i dati.
    sr_data = SmartRiderData()
    
    # Verifica che il dump sia sufficientemente lungo (assumiamo MAX_BLOCKS * 16 byte)
    if len(nfc_data) < MAX_BLOCKS * 16:
        return "Error: dump too short."
    
    # Verifica la chiave: il blocco trailer del settore 0 (blocco 3) deve contenere STANDARD_KEYS[0]
    trailer0 = get_block(nfc_data, 3)
    if trailer0[0:6] != STANDARD_KEYS[0]:
        return "Error: Key verification failed for sector 0."
    
    # Alcuni blocchi "required" (da un array statico) devono essere letti; in Python verifichiamo la lunghezza
    required_blocks = [14, 4, 5, 1, 52, 50, 0]
    for blk in required_blocks:
        if blk >= MAX_BLOCKS:
            return f"Error: required block {blk} out of range."
        # Simuliamo che il blocco sia letto se il dump ha i dati necessari.
    
    # Estrai dati da specifici blocchi
    # Balance: dal blocco 14, a partire dal byte 7 (2 byte, little-endian)
    block14 = get_block(nfc_data, 14)
    sr_data.balance = get_number_le(block14, 7, 2)
    # Issued and expiry days: dal blocco 4, a partire dai byte 16 e 18 (2 byte ciascuno)
    block4 = get_block(nfc_data, 4)
    sr_data.issued_days = get_number_le(block4, 16, 2)
    sr_data.expiry_days = get_number_le(block4, 18, 2)
    # Purchase cost: dal blocco 0, a partire dal byte 14 (2 byte, little-endian)
    block0 = get_block(nfc_data, 0)
    sr_data.purchase_cost = get_number_le(block0, 14, 2)
    # Auto-load threshold e value: dal blocco 4, a partire dai byte 20 e 22
    sr_data.auto_load_threshold = get_number_le(block4, 20, 2)
    sr_data.auto_load_value = get_number_le(block4, 22, 2)
    # Token: dal blocco 5, byte 8
    block5 = get_block(nfc_data, 5)
    sr_data.token = block5[8]
    # Card serial number: dal blocco 1, bytes 6-10, convertito in esadecimale (11 caratteri)
    block1 = get_block(nfc_data, 1)
    sr_data.card_serial_number = block1[6:11].hex().upper()
    
    # Leggi i viaggi da blocchi 40 a 52, saltando 43, 47 e 51
    sr_data.trips = []
    for block_number in range(40, 53):
        if block_number in (43, 47, 51):
            continue
        # Assumiamo che il blocco sia "letto" (il dump deve contenere 16 byte per ciascun blocco)
        block_data = get_block(nfc_data, block_number)
        # Se il blocco non è pieno di 0xFF, consideralo valido
        if block_data == b'\xFF' * 16:
            continue
        trip = parse_trip_data(block_data, block_number)
        sr_data.trips.append(trip)
        if len(sr_data.trips) >= MAX_TRIPS:
            break
    
    # Ordina i viaggi per timestamp decrescente
    sr_data.trips.sort(key=lambda t: t.timestamp, reverse=True)
    
    # Costruisci l'output
    output_lines = []
    output_lines.append("SmartRider")
    output_lines.append(f"Balance: ${sr_data.balance // 100}.{sr_data.balance % 100:02d}")
    output_lines.append(f"Concession: {get_concession_type(sr_data.token)}")
    serial = sr_data.card_serial_number
    if serial.startswith("00"):
        serial = "SR0" + serial[2:]
    output_lines.append(f"Serial: {serial}")
    output_lines.append(f"Total Cost: ${sr_data.purchase_cost // 100}.{sr_data.purchase_cost % 100:02d}")
    output_lines.append(f"Auto-Load: ${sr_data.auto_load_threshold // 100}.{sr_data.auto_load_threshold % 100:02d}/"
                        f"${sr_data.auto_load_value // 100}.{sr_data.auto_load_value % 100:02d}")
    output_lines.append("Tag On/Off History")
    for trip in sr_data.trips:
        date_str = calculate_date(trip.timestamp)
        cost = trip.cost
        if cost > 0:
            output_lines.append(f"{date_str} {'+' if trip.tap_on else '-'} ${cost // 100}.{cost % 100:02d} {trip.route}")
        else:
            output_lines.append(f"{date_str} {'+' if trip.tap_on else '-'} {trip.route}")
    
    return "\n".join(output_lines)

def main():
    if len(sys.argv) != 2:
        print("Usage: python smartrider.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        result = smartrider_parse(card_data)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
