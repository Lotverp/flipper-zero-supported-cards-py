#!/usr/bin/env python3
import sys
from datetime import datetime, timedelta

OPAL_FILE_SIZE = 16

# Opal card bitfield definitions (per un intero a 128 bit, little-endian):
#   serial: bits 0-31
#   check_digit: bits 32-35 (4 bit)
#   blocked: bit 36 (1 bit)
#   txn_number: bits 37-52 (16 bit)
#   balance: bits 53-73 (21 bit, two's complement)
#   days: bits 74-88 (15 bit)
#   minutes: bits 89-99 (11 bit)
#   mode: bits 100-102 (3 bit)
#   usage: bits 103-106 (4 bit)
#   auto_topup: bit 107 (1 bit)
#   weekly_journeys: bits 108-111 (4 bit)
#   checksum: bits 112-127 (16 bit)
#
# Le nostre conversioni considerano solo i campi rilevanti per l’output.

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
    "Tap off: distance fare",
    "Tap off: flat fare",
    "Automated tap off: failed to tap off",
    "Tap off: end of trip without start",
    "Tap off: reversal",
    "Tap on: rejected",
    "Unknown usage"
]

def opal_days_minutes_to_datetime(days: int, minutes: int) -> datetime:
    """Converte i campi 'days' e 'minutes' in una data, partendo dal 1980-01-01."""
    base = datetime(1980, 1, 1)
    return base + timedelta(days=days, minutes=minutes)

def parse_opal(file_data: bytes) -> str:
    if len(file_data) < OPAL_FILE_SIZE:
        return "Error: file too short."
    
    # Legge 16 byte in little-endian come intero a 128 bit
    raw = int.from_bytes(file_data[:OPAL_FILE_SIZE], byteorder='little', signed=False)
    
    serial      = raw & ((1 << 32) - 1)
    check_digit = (raw >> 32) & 0xF
    if check_digit > 9:
        return "Error: invalid check digit."
    blocked     = (raw >> 36) & 0x1
    txn_number  = (raw >> 37) & ((1 << 16) - 1)
    balance_raw = (raw >> 53) & ((1 << 21) - 1)
    # Sign extend 21-bit balance
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
    # checksum field non viene usato nel parser
    
    is_negative = balance < 0
    sign_str = "-" if is_negative else ""
    bal_abs = abs(balance)
    balance_dollars = bal_abs // 100
    balance_cents   = bal_abs % 100

    # Formatta il numero della carta:
    # Serial number in Opal card è composto da:
    #   serial2 = serial // 10000000
    #   serial3 = (serial // 1000) % 10000
    #   serial4 = serial % 1000
    serial2 = serial // 10000000
    serial3 = (serial // 1000) % 10000
    serial4 = serial % 1000
    card_number_str = f"3085 22{serial2:02d} {serial3:04d} {serial4:03d}{check_digit:1d}"
    
    # Regola per "Manly Ferry": se usage_field è tra 4 e 6, mode è 4 e usage = usage_field - 3.
    is_manly_ferry = (usage_field >= 4 and usage_field <= 6)
    if is_manly_ferry:
        mode = 4
        usage = usage_field - 3
    else:
        mode = mode_field
        usage = usage_field

    if mode > 4:
        mode_str = "Unknown mode"
    else:
        mode_str = opal_modes[mode]
    if usage > 10:
        usage_str = "Unknown usage"
    else:
        usage_str = opal_usages[usage]
    
    dt = opal_days_minutes_to_datetime(days_field, minutes_field)
    timestamp_str = dt.strftime("%Y-%m-%d at %H:%M:%S")
    
    output_lines = [
        f"Opal: ${sign_str}{balance_dollars}.{balance_cents:02d}",
        f"No.: {card_number_str}",
        f"{mode_str}, {usage_str}",
        timestamp_str,
        f"Weekly journeys: {weekly_journeys}, Txn #{txn_number}"
    ]
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
        result = parse_opal(file_data)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
