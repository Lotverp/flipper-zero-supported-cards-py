#!/usr/bin/env python3
import sys

# Dimensione di un blocco (16 byte) e lunghezza totale attesa per una 1K
MF_CLASSIC_BLOCK_SIZE = 16
EXPECTED_DUMP_SIZE = 1024

# Costanti per i settori e blocchi usati
ROOM_SECTOR = 1
VIP_SECTOR = 5
ROOM_SECTOR_KEY_BLOCK = 7
VIP_SECTOR_KEY_BLOCK = 23
ACCESS_INFO_BLOCK = 5
H_WORLD_YEAR_OFFSET = 2000

# Chiavi predefinite: liste per 16 settori (0..15)
# hworld_standard_keys[ROOM_SECTOR] è usato per il controllo della chiave nel blocco ROOM_SECTOR_KEY_BLOCK (blocco 7)
hworld_standard_keys = [
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 0
    {"a": 0x543071543071, "b": 0x5F01015F0101},  # settore 1
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 2
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 3
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 4
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 5
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 6
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 7
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 8
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 9
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 10
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 11
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 12
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 13
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 14
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 15
]

# hworld_vip_keys[VIP_SECTOR] (settore 5) usato per determinare se la carta è VIP
hworld_vip_keys = [
    {"a": 0x000000000000, "b": 0xFFFFFFFFFFFF},  # settore 0
    {"a": 0x543071543071, "b": 0x5F01015F0101},  # settore 1
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 2
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 3
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 4
    {"a": 0xFFFFFFFFFFFF, "b": 0x200510241234},  # settore 5
    {"a": 0xFFFFFFFFFFFF, "b": 0x200510241234},  # settore 6
    {"a": 0xFFFFFFFFFFFF, "b": 0x200510241234},  # settore 7
    {"a": 0xFFFFFFFFFFFF, "b": 0x200510241234},  # settore 8
    {"a": 0xFFFFFFFFFFFF, "b": 0x200510241234},  # settore 9
    {"a": 0xFFFFFFFFFFFF, "b": 0x200510241234},  # settore 10
    {"a": 0xFFFFFFFFFFFF, "b": 0x200510241234},  # settore 11
    {"a": 0xFFFFFFFFFFFF, "b": 0x200510241234},  # settore 12
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 13
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 14
    {"a": 0xFFFFFFFFFFFF, "b": 0xFFFFFFFFFFFF},  # settore 15
]

# Funzione helper per estrarre un blocco dato il numero (ogni blocco è 16 byte)
def get_block(card_data: bytes, block_num: int) -> bytes:
    start = block_num * MF_CLASSIC_BLOCK_SIZE
    return card_data[start:start+MF_CLASSIC_BLOCK_SIZE]

# Funzione per estrarre un numero da una sezione di byte
def get_number(data: bytes, start: int, length: int) -> int:
    return int.from_bytes(data[start:start+length], byteorder='big')

def parse_hworld_card(card_data: bytes) -> str:
    if len(card_data) < EXPECTED_DUMP_SIZE:
        return "Errore: dump della carta troppo corto."
    
    # Controlla che la carta sia di tipo 1K (in questa conversione assumiamo sempre 1K)
    # Estrai il blocco ROOM_SECTOR_KEY_BLOCK (blocco 7)
    block7 = get_block(card_data, ROOM_SECTOR_KEY_BLOCK)
    # I primi 6 byte sono la chiave A
    data_room_sec_key_a = int.from_bytes(block7[0:6], 'big')
    # Gli ultimi 6 byte (offset 10-15) sono la chiave B
    data_room_sec_key_b = int.from_bytes(block7[10:16], 'big')
    
    std_key = hworld_standard_keys[ROOM_SECTOR]
    if data_room_sec_key_a != std_key["a"] or data_room_sec_key_b != std_key["b"]:
        return "Errore: chiave statica della stanza non corrisponde."
    
    # Verifica se la carta è VIP: dal blocco VIP_SECTOR_KEY_BLOCK (blocco 23), prendi 6 byte a partire dall'offset 10
    block23 = get_block(card_data, VIP_SECTOR_KEY_BLOCK)
    data_vip_sec_key_b = int.from_bytes(block23[10:16], 'big')
    is_vip = (data_vip_sec_key_b == hworld_vip_keys[VIP_SECTOR]["b"])
    
    # Dal blocco ACCESS_INFO_BLOCK (blocco 5) estrai le informazioni
    block5 = get_block(card_data, ACCESS_INFO_BLOCK)
    # Room floor (offset 13) e room num (offset 14)
    room_floor = block5[13]
    room_num = block5[14]
    
    # Check-in data & time: offset 2..6
    check_in_year = block5[2] + H_WORLD_YEAR_OFFSET
    check_in_month = block5[3]
    check_in_day = block5[4]
    check_in_hour = block5[5]
    check_in_minute = block5[6]
    
    # Expiration data & time: offset 7..11
    expire_year = block5[7] + H_WORLD_YEAR_OFFSET
    expire_month = block5[8]
    expire_day = block5[9]
    expire_hour = block5[10]
    expire_minute = block5[11]
    
    # Format output
    output_lines = []
    output_lines.append("H World Card")
    output_lines.append("VIP card" if is_vip else "Standard room key")
    output_lines.append(f"Room Num: {room_floor}{room_num:02d}")
    output_lines.append(f"Check-in Date: \n{check_in_year:04d}-{check_in_month:02d}-{check_in_day:02d}\n{check_in_hour:02d}:{check_in_minute:02d}:00")
    output_lines.append(f"Expiration Date: \n{expire_year:04d}-{expire_month:02d}-{expire_day:02d}\n{expire_hour:02d}:{expire_minute:02d}:00")
    
    return "\n".join(output_lines)

def main():
    if len(sys.argv) != 2:
        print("Uso: python hworld.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            card_data = f.read()
        result = parse_hworld_card(card_data)
        print(result)
    except Exception as e:
        print("Errore:", e)

if __name__ == '__main__':
    main()
