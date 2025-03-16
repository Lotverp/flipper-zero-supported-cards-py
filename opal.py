#!/usr/bin/env python3
import sys
from datetime import datetime, timedelta

# Costanti di Opal
OPAL_FILE_SIZE = 16  # 16 byte
opal_modes = [
    "Rail / Metro",
    "Ferry / Light Rail",
    "Bus",
    "Unknown mode",
    "Manly Ferry"
]
opal_usages = [
    "New / Unused",
    "Tap on: new journey",
    "Tap on: transfer from same mode",
    "Tap on: transfer from other mode",
    "Manly Ferry: new journey",
    "Manly Ferry: transfer from ferry",
    "Manly Ferry: transfer from other",
    "Tap off: distance fare",
    "Tap off: flat fare",
    "Automated tap off: failed to tap off",
    "Tap off: end of trip without start",
    "Tap off: reversal",
    "Tap on: rejected",
    "Unknown usage"
]

def opal_days_minutes_to_datetime(days: int, minutes: int) -> datetime:
    """
    Converte il campo 'days' e 'minutes' dell'Opal card in una data e ora.
    Si assume che 'days' rappresenti il numero di giorni trascorsi dal 1980-01-01,
    e 'minutes' il numero di minuti trascorsi dall'inizio del giorno.
    """
    # Partenza: 1980-01-01
    base = datetime(1980, 1, 1)
    dt = base + timedelta(days=days, minutes=minutes)
    return dt

def parse_opal(file_data: bytes) -> str:
    if len(file_data) < OPAL_FILE_SIZE:
        return "Errore: dump della carta troppo corto."

    # Legge i 16 byte del file Opal
    raw = int.from_bytes(file_data[:OPAL_FILE_SIZE], byteorder='little')
    
    # Estrae i campi (bitfields). Gli offset sono definiti per un sistema little-endian:
    # serial: bits 0-31
    # check_digit: bits 32-35
    # blocked: bit 36
    # txn_number: bits 37-52 (16 bits)
    # balance: bits 53-73 (21 bits, in two's complement)
    # days: bits 74-88 (15 bits)
    # minutes: bits 89-99 (11 bits)
    # mode: bits 100-102 (3 bits)
    # usage: bits 103-106 (4 bits)
    # auto_topup: bit 107 (1 bit)
    # weekly_journeys: bits 108-111 (4 bits)
    # checksum: bits 112-127 (16 bits)
    serial      = raw & ((1 << 32) - 1)
    check_digit = (raw >> 32) & 0xF
    blocked     = (raw >> 36) & 0x1
    txn_number  = (raw >> 37) & ((1 << 16) - 1)
    balance_raw = (raw >> 53) & ((1 << 21) - 1)
    # Sign extend 21-bit balance:
    if balance_raw & (1 << 20):
        balance = balance_raw - (1 << 21)
    else:
        balance = balance_raw
    days_field    = (raw >> 74) & ((1 << 15) - 1)
    minutes_field = (raw >> 89) & ((1 << 11) - 1)
    mode_field    = (raw >> 100) & 0x7
    usage_field   = (raw >> 103) & 0xF
    auto_topup    = (raw >> 107) & 0x1
    weekly_journeys = (raw >> 108) & 0xF
    checksum      = (raw >> 112) & 0xFFFF

    # Verifica check_digit (deve essere 0-9)
    if check_digit > 9:
        return "Errore: check digit non valido."
    
    # Processa il saldo
    is_negative = balance < 0
    sign = "-" if is_negative else ""
    bal_abs = abs(balance)
    balance_dollars = bal_abs // 100
    balance_cents   = bal_abs % 100

    # Dividi il numero seriale in parti
    serial2 = serial // 10000000
    serial3 = (serial // 1000) % 10000
    serial4 = serial % 1000

    # Determina se è un "Manly Ferry" in base al campo usage
    is_manly_ferry = 4 <= usage_field <= 6
    mode = 4 if is_manly_ferry else mode_field
    usage = usage_field - 3 if is_manly_ferry else usage_field

    mode_str = opal_modes[3] if mode > 4 else opal_modes[mode]
    usage_str = opal_usages[13] if usage > 12 else opal_usages[usage]

    # Converti il campo days e minutes in una data e ora
    dt = opal_days_minutes_to_datetime(days_field, minutes_field)
    timestamp_str = dt.strftime("%Y-%m-%d at %H:%M:%S")

    # Componi l'output
    output_lines = []
    output_lines.append(f"\e#Opal: ${sign}{balance_dollars}.{balance_cents:02d}")
    output_lines.append(f"No.: 3085 22{serial2:02d} {serial3:04d} {serial4:03d}{check_digit:1d}")
    output_lines.append(f"{mode_str}, {usage_str}")
    output_lines.append(timestamp_str)
    output_lines.append(f"Weekly journeys: {weekly_journeys}, Txn #{txn_number}")
    if auto_topup:
        output_lines.append("Auto-topup enabled")
    if blocked:
        output_lines.append("Card blocked")
    
    return "\n".join(output_lines)

def main():
    if len(sys.argv) != 2:
        print("Usage: python opal.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            file_data = f.read()
        if len(file_data) < OPAL_FILE_SIZE:
            print("Errore: dump della carta troppo corto.")
            sys.exit(1)
        result = parse_opal(file_data)
        print(result)
    except Exception as e:
        print("Errore:", e)

if __name__ == '__main__':
    main()
