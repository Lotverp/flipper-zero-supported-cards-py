#!/usr/bin/env python3
import sys
import struct
from datetime import datetime, timedelta

MF_CLASSIC_BLOCK_SIZE = 16
EXPECTED_DUMP_SIZE = 1024

# Funzione per estrarre un blocco da un dump
def get_block(card_data: bytes, block_num: int) -> bytes:
    start = block_num * MF_CLASSIC_BLOCK_SIZE
    return card_data[start:start + MF_CLASSIC_BLOCK_SIZE]

# Funzione per convertire minuti in datetime, partendo dal 31 dicembre dell'anno precedente
def from_minutes_to_datetime(minutes: int, start_year: int) -> datetime:
    # Calcola il timestamp partendo dal 31 dicembre dell'anno precedente
    start_dt = datetime(start_year - 1, 12, 31)
    start_timestamp = int(start_dt.timestamp())
    final_timestamp = start_timestamp + minutes * 60
    return datetime.fromtimestamp(final_timestamp)

# Chiavi per Plantain: array per 1K e 4K (usiamo quelle fornite dal file C)
plantain_1k_keys = [
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xe56ac127dd45, "b": 0x19fc84a3784b},
    {"a": 0x77dabc9825e1, "b": 0x9764fec3154a},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0x26973ea74321, "b": 0xd27058c6e2c7},
    {"a": 0xeb0a8ff88ade, "b": 0x578a9ada41e3},
    {"a": 0xea0fd73cb149, "b": 0x29c35fa068fb},
    {"a": 0xc76bf71a2509, "b": 0x9ba241db3f56},
    {"a": 0xacffffffffff, "b": 0x71f3a315ad26},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
]

plantain_4k_keys = [
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xe56ac127dd45, "b": 0x19fc84a3784b},
    {"a": 0x77dabc9825e1, "b": 0x9764fec3154a},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0x26973ea74321, "b": 0xd27058c6e2c7},
    {"a": 0xeb0a8ff88ade, "b": 0x578a9ada41e3},
    {"a": 0xea0fd73cb149, "b": 0x29c35fa068fb},
    {"a": 0xc76bf71a2509, "b": 0x9ba241db3f56},
    {"a": 0xacffffffffff, "b": 0x71f3a315ad26},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0xffffffffffff, "b": 0xffffffffffff},
    {"a": 0x72f96bdd3714, "b": 0x462225cd34cf},
    {"a": 0x044ce1872bc3, "b": 0x8c90c70cff4a},
    {"a": 0xbc2d1791dec1, "b": 0xca96a487de0b},
    {"a": 0x8791b2ccb5c4, "b": 0xc956c3b80da3},
    {"a": 0x8e26e45e7d65, "b": 0x8e65b3af7d22},
    {"a": 0x0f318130ed18, "b": 0x0c420a20e056},
    {"a": 0x045ceca15535, "b": 0x31bec3d9e510},
    {"a": 0x9d993c5d4ef4, "b": 0x86120e488abf},
    {"a": 0xc65d4eaa645b, "b": 0xb69d40d1a439},
    {"a": 0x3a8a139c20b4, "b": 0x8818a9c5d406},
    {"a": 0xbaff3053b496, "b": 0x4b7cb25354d3},
    {"a": 0x7413b599c4ea, "b": 0xb0a2AAF3A1BA},
    {"a": 0x0ce7cd2cc72b, "b": 0xfa1fbb3f0f1f},
    {"a": 0x0be5fac8b06a, "b": 0x6f95887a4fd3},
    {"a": 0x0eb23cc8110b, "b": 0x04dc35277635},
    {"a": 0xbc4580b7f20b, "b": 0xd0a4131fb290},
    {"a": 0x7a396f0d633d, "b": 0xad2bdc097023},
    {"a": 0xa3faa6daff67, "b": 0x7600e889adf9},
    {"a": 0xfd8705e721b0, "b": 0x296fc317a513},
    {"a": 0x22052b480d11, "b": 0xe19504c39461},
    {"a": 0xa7141147d430, "b": 0xff16014fefc7},
    {"a": 0x8a8d88151a00, "b": 0x038b5f9b5a2a},
    {"a": 0xb27addfb64b0, "b": 0x152fd0c420a7},
    {"a": 0x7259fa0197c6, "b": 0x5583698df085},
]

def plantain_get_card_config(card_type: str):
    if card_type.lower() == "1k":
        return {"data_sector": 8, "keys": plantain_1k_keys}
    elif card_type.lower() == "4k":
        return {"data_sector": 8, "keys": plantain_4k_keys}
    else:
        return None

def plantain_verify(card_data: bytes, card_type: str) -> bool:
    config = plantain_get_card_config(card_type)
    if config is None:
        return False
    sector = config["data_sector"]
    trailer_block = get_block(card_data, sector * 4 + 3)
    stored_key = int.from_bytes(trailer_block[0:6], byteorder='big')
    expected_key = config["keys"][sector]["a"]
    return stored_key == expected_key

def plantain_read(card_data: bytes, card_type: str) -> bool:
    return len(card_data) >= EXPECTED_DUMP_SIZE

def plantain_parse(card_data: bytes, card_type: str) -> str:
    if len(card_data) < EXPECTED_DUMP_SIZE:
        return "Error: card dump too short."
    config = plantain_get_card_config(card_type)
    if config is None:
        return "Error: unsupported card type."
    sector = config["data_sector"]
    # Verify key in trailer
    trailer_block = get_block(card_data, sector * 4 + 3)
    stored_key = int.from_bytes(trailer_block[0:6], byteorder='big')
    expected_key = config["keys"][sector]["a"]
    if stored_key != expected_key:
        return "Error: key verification failed."
    
    output = "Plantain card\n"
    
    # Extract UID: assume UID is in the first 4 or 7 bytes of the dump.
    uid = card_data[0:UID_LENGTH]
    if len(uid) not in (4, 7):
        return "Error: invalid UID length."
    card_number_bytes = uid[::-1]  # reverse the UID bytes
    card_number = int.from_bytes(card_number_bytes, byteorder='big')
    # Format card number as hex groups (es. "3078" in "9643 3078 ...")
    card_str = f"{card_number:X}"
    # For simplicity, non applichiamo formattazioni complicate, mostriamo l'UID in reverse order.
    output += "Number: " + " ".join(f"{b:02X}" for b in card_number_bytes) + "\n"
    
    # Balance: read block 16, reverse 4 bytes
    block16 = get_block(card_data, 16)
    balance = 0
    for i in range(4):
        balance = (balance << 8) | block16[3 - i]
    output += f"Balance: {balance // 100}.{balance % 100:02d} rub\n"
    
    # Trips: from block 21: first two bytes: trips_metro, trips_ground
    block21 = get_block(card_data, 21)
    trips_metro = block21[0]
    trips_ground = block21[1]
    total_trips = trips_metro + trips_ground
    output += f"Trips: {total_trips}\n"
    
    # Last trip time: from block 21, bytes 1-3 (big-endian)
    last_trip_timestamp = 0
    for i in range(3):
        last_trip_timestamp = (last_trip_timestamp << 8) | block21[4 - i]
    last_trip = from_minutes_to_datetime(last_trip_timestamp + 24 * 60, 2010)
    output += "Trip start: " + last_trip.strftime("%d.%m.%Y %H:%M") + "\n"
    
    # Validator: from block 20, bytes 4-5
    block20 = get_block(card_data, 20)
    validator = (block20[5] << 8) | block20[4]
    output += f"Validator: {validator}\n"
    
    # Tariff: from block 20, bytes 6-7
    fare = (block20[7] << 8) | block20[6]
    output += f"Tariff: {fare // 100} rub\n"
    
    output += f"Trips (Metro): {trips_metro}\n"
    output += f"Trips (Ground): {trips_ground}\n"
    
    # Last payment: from block 18, bytes 1-3 (big-endian)
    block18 = get_block(card_data, 18)
    last_payment_timestamp = 0
    for i in range(3):
        last_payment_timestamp = (last_payment_timestamp << 8) | block18[4 - i]
    last_payment = from_minutes_to_datetime(last_payment_timestamp + 24 * 60, 2010)
    output += "Last pay: " + last_payment.strftime("%d.%m.%Y %H:%M") + "\n"
    
    # Last payment amount: from block 18, bytes 8-10 (big-endian) divided by 100
    last_payment_amount = ((block18[10] << 16) | (block18[9] << 8) | block18[8]) // 100
    output += f"Amount: {last_payment_amount} rub"
    
    return output

def main():
    if len(sys.argv) != 3:
        print("Usage: python plantain.py <dump_file> <card_type: 1k or 4k>")
        sys.exit(1)
    dump_file = sys.argv[1]
    card_type = sys.argv[2]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        if len(card_data) < EXPECTED_DUMP_SIZE:
            print("Error: Card dump too short.")
            sys.exit(1)
        if not plantain_read(card_data, card_type):
            print("Error: Reading card failed.")
            sys.exit(1)
        result = plantain_parse(card_data, card_type)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
