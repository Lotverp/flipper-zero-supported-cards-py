#!/usr/bin/env python3
import sys
from datetime import datetime

MF_CLASSIC_BLOCK_SIZE = 16
EXPECTED_DUMP_SIZE = 1024

# Funzione helper per estrarre un blocco (16 byte) dal dump
def get_block(card_data: bytes, block_num: int) -> bytes:
    start = block_num * MF_CLASSIC_BLOCK_SIZE
    return card_data[start:start + MF_CLASSIC_BLOCK_SIZE]

# Funzione per calcolare il primo blocco di un settore (per 1K: 4 blocchi per settore)
def first_block_of_sector(sector: int) -> int:
    return sector * 4

# Funzioni per leggere un intero da una sequenza di byte
def get_number_le(data: bytes, start: int, length: int) -> int:
    return int.from_bytes(data[start:start+length], byteorder='little')

def get_number_be(data: bytes, start: int, length: int) -> int:
    return int.from_bytes(data[start:start+length], byteorder='big')

# Chiavi predefinite per Kazan (versione 1 e 2; per il settore 8, usato per i ticket)
kazan_1k_keys_v1 = [
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 0
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 1
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 2
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 3
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 4
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 5
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 6
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 7
    {"a": 0xE954024EE754, "b": 0x0CD464CDC100},  # 8
    {"a": 0xBC305FE2DA65, "b": 0xCF0EC6ACF2F9},  # 9
    {"a": 0xF7A545095C49, "b": 0x6862FD600F78},  # 10
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 11
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 12
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 13
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 14
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 15
]

kazan_1k_keys_v2 = [
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 0
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 1
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 2
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 3
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 4
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 5
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 6
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 7
    {"a": 0x2058EAEE8446, "b": 0xCB9B23815F87},  # 8
    {"a": 0x492F3744A1DC, "b": 0x6B770AADA274},  # 9
    {"a": 0xF7A545095C49, "b": 0x6862FD600F78},  # 10
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 11
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 12
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 13
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 14
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # 15
]

# Tipi di abbonamento
SUBSCRIPTION_TYPE_UNKNOWN = 0
SUBSCRIPTION_TYPE_PURSE = 1
SUBSCRIPTION_TYPE_ABONNEMENT_BY_TIME = 2
SUBSCRIPTION_TYPE_ABONNEMENT_BY_TRIPS = 3

def get_subscription_type(value: int) -> (int, str):
    if value == 0x51:
        return SUBSCRIPTION_TYPE_ABONNEMENT_BY_TIME, "Social. Adult"
    elif value == 0x67:
        return SUBSCRIPTION_TYPE_ABONNEMENT_BY_TIME, "Ground electric transport. 1 month"
    elif value == 0x0F:
        return SUBSCRIPTION_TYPE_ABONNEMENT_BY_TRIPS, "Underground only"
    elif value == 0x6D:
        return SUBSCRIPTION_TYPE_ABONNEMENT_BY_TRIPS, "Tram. 60 minutes. Transfer. 10 trips"
    elif value == 0x53:
        return SUBSCRIPTION_TYPE_PURSE, "Standard purse"
    elif value == 0x01:
        return SUBSCRIPTION_TYPE_ABONNEMENT_BY_TRIPS, "Token"
    else:
        return SUBSCRIPTION_TYPE_UNKNOWN, "Unknown"

def parse_kazan_card(card_data: bytes) -> str:
    if len(card_data) < EXPECTED_DUMP_SIZE:
        return "Errore: dump della carta troppo corto."
    
    # Settore ticket e balance
    ticket_sector = 8
    balance_sector = 9
    
    # Verifica chiavi nel trailer del settore ticket (settore 8: blocco = 8*4+3 = 35)
    ticket_trailer = get_block(card_data, ticket_sector * 4 + 3)
    key_a = int.from_bytes(ticket_trailer[0:6], 'big')
    key_b = int.from_bytes(ticket_trailer[10:16], 'big')
    
    valid_key_a = (key_a == kazan_1k_keys_v1[ticket_sector]["a"] or key_a == kazan_1k_keys_v2[ticket_sector]["a"])
    valid_key_b = (key_b == kazan_1k_keys_v1[ticket_sector]["b"] or key_b == kazan_1k_keys_v2[ticket_sector]["b"])
    if not (valid_key_a and valid_key_b):
        return "Errore: chiave del ticket sector non verificata."
    
    # Estrae dati dal settore ticket
    start_block = ticket_sector * 4
    ticket_block = get_block(card_data, start_block)
    # I dati di interesse iniziano dall'offset 6 del blocco
    offset = 6
    sub_value = ticket_block[offset]
    subscription_type, tariff_name = get_subscription_type(sub_value)
    
    # Data di validità "valid from": bytes offset+1, +2, +3 (anno, mese, giorno)
    valid_from_year = 2000 + ticket_block[offset + 1]
    valid_from_month = ticket_block[offset + 2]
    valid_from_day = ticket_block[offset + 3]
    try:
        valid_from = datetime(valid_from_year, valid_from_month, valid_from_day)
    except Exception:
        return "Errore: data 'valid from' non valida."
    
    # Data di validità "valid to": bytes offset+4, +5, +6
    valid_to_year = 2000 + ticket_block[offset + 4]
    valid_to_month = ticket_block[offset + 5]
    valid_to_day = ticket_block[offset + 6]
    try:
        valid_to = datetime(valid_to_year, valid_to_month, valid_to_day)
    except Exception:
        return "Errore: data 'valid to' non valida."
    
    # Dati dell'ultimo viaggio: dal blocco (start_block + 2), a partire dall'offset 1 (5 byte: anno, mese, giorno, ora, minuto)
    last_trip_block = get_block(card_data, start_block + 2)
    lt_year = 2000 + last_trip_block[1]
    lt_month = last_trip_block[2]
    lt_day = last_trip_block[3]
    lt_hour = last_trip_block[4]
    lt_minute = last_trip_block[5]
    last_trip_valid = (last_trip_block[1] | last_trip_block[2] | last_trip_block[3]) != 0 and (lt_day < 32 and lt_month < 13 and lt_hour < 24 and lt_minute < 60)
    last_trip_str = ""
    if last_trip_valid:
        try:
            last_trip = datetime(lt_year, lt_month, lt_day, lt_hour, lt_minute)
            last_trip_str = f"Last trip: {last_trip.strftime('%Y-%m-%d %H:%M')}"
        except Exception:
            last_trip_str = ""
    
    # Dal settore balance (settore 9, blocco = 9*4 = 36) si legge il contatore/trip counter (primi 4 byte, little endian)
    balance_block = get_block(card_data, balance_sector * 4)
    trip_counter = int.from_bytes(balance_block[0:4], 'little')
    
    # Numero della carta: presupponiamo che l'UID sia nei primi 4 byte del dump
    uid = card_data[0:4]
    card_number = int.from_bytes(uid, 'little')
    
    # Componi l'output
    output_lines = []
    output_lines.append("Kazan transport card")
    output_lines.append(f"Card number: {card_number}")
    output_lines.append(f"Valid from: {valid_from.strftime('%Y-%m-%d')}")
    output_lines.append(f"Valid to: {valid_to.strftime('%Y-%m-%d')}")
    
    if subscription_type == SUBSCRIPTION_TYPE_PURSE:
        output_lines.append("Type: purse")
        output_lines.append(f"Balance: {trip_counter} RUR")
    elif subscription_type == SUBSCRIPTION_TYPE_ABONNEMENT_BY_TRIPS:
        output_lines.append("Type: abonnement")
        output_lines.append(f"Tariff: {tariff_name}")
        output_lines.append(f"Trips left: {trip_counter}")
    elif subscription_type == SUBSCRIPTION_TYPE_ABONNEMENT_BY_TIME:
        output_lines.append("Type: abonnement")
        output_lines.append(f"Tariff: {tariff_name}")
        output_lines.append(f"Total valid time: {trip_counter} days")
    else:
        output_lines.append("Type: unknown")
        output_lines.append(f"Tariff: {tariff_name}")
        output_lines.append(f"Counter: {trip_counter}")
    
    if last_trip_str:
        output_lines.append(last_trip_str)
    
    return "\n".join(output_lines)

def main():
    if len(sys.argv) != 2:
        print("Uso: python kazan.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        result = parse_kazan_card(card_data)
        print(result)
    except Exception as e:
        print("Errore:", e)

if __name__ == '__main__':
    main()
