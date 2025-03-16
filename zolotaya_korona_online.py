#!/usr/bin/env python3
import sys

# Costanti
BLOCK_SIZE = 16
# Settori (per una carta 1K, ogni settore ha 4 blocchi)
TRIP_SECTOR_NUM = 4
INFO_SECTOR_NUM = 15

def get_block(data: bytes, block_num: int) -> bytes:
    """Restituisce il blocco (16 byte) identificato da block_num."""
    start = block_num * BLOCK_SIZE
    return data[start:start+BLOCK_SIZE]

def bytes_to_int_be(b: bytes) -> int:
    """Converte una sequenza di byte in intero (big-endian)."""
    return int.from_bytes(b, byteorder='big')

def bcd_to_int(b: bytes) -> (int, bool):
    """
    Converte una sequenza di byte in formato BCD in un intero.
    Restituisce una tupla (valore, valid) in cui valid è True se tutti i nibble sono ≤ 9.
    """
    total = 0
    for byte in b:
        high = (byte >> 4) & 0x0F
        low = byte & 0x0F
        if high > 9 or low > 9:
            return (0, False)
        total = total * 100 + high * 10 + low
    return (total, True)

def parse_online_card_tariff(tariff: int) -> str:
    """Ritorna il nome del tariffario in base al valore a 16 bit."""
    if tariff == 0x0100:
        return "Standart (online)"
    elif tariff in (0x0101, 0x0121):
        return "Standart (airtag)"
    elif tariff == 0x0401:
        return "Student (50% discount)"
    elif tariff == 0x0402:
        return "Student (travel)"
    elif tariff == 0x0002:
        return "School (50% discount)"
    elif tariff == 0x0505:
        return "Social (large families)"
    elif tariff == 0x0528:
        return "Social (handicapped)"
    else:
        return "Unknown"

def zolotaya_korona_online_parse(dump: bytes) -> str:
    """
    Parser per la Zolotaya Korona Online card:
      - Dal settore INFO (settore 15, blocco 60) a partire dall'offset 3,
        estrae il prefisso (2 byte BCD) e il postfix (8 byte BCD, diviso per 10)
      - Dal settore INFO, a partire dall'offset 1 del blocco 60, estrae il tariffario (2 byte BE)
      - Dal settore TRIP (settore 4, blocco 16) legge un byte come region number.
      - L'output viene formattato in una stringa multilinea.
    """
    # Calcola il numero del primo blocco di un settore (per 1K, settore * 4)
    def first_block_of_sector(sector: int) -> int:
        return sector * 4

    # INFO SECTOR: Settore 15
    start_info_block = first_block_of_sector(INFO_SECTOR_NUM)
    block_info = get_block(dump, start_info_block)
    
    # A partire dall'offset 3, leggi 2 byte BCD per il prefisso
    prefix_bcd = block_info[3:5]
    card_number_prefix, valid = bcd_to_int(prefix_bcd)
    if not valid or card_number_prefix != 9643:
        return "Error: invalid card number prefix."
    # Dal medesimo blocco, a partire dall'offset 5, leggi 8 byte BCD per il postfix e dividili per 10
    postfix_bcd = block_info[5:13]
    card_number_postfix, valid = bcd_to_int(postfix_bcd)
    if not valid:
        return "Error: invalid card number postfix."
    card_number_postfix //= 10

    # Tariffario: dal blocco INFO, a partire dall'offset 1, leggi 2 byte in BE
    tariff_bytes = block_info[1:3]
    tariff = bytes_to_int_be(tariff_bytes)
    tariff_name = parse_online_card_tariff(tariff)

    # TRIP SECTOR: Settore 4
    start_trip_block = first_block_of_sector(TRIP_SECTOR_NUM)
    block_trip = get_block(dump, start_trip_block)
    # Leggi 1 byte (offset 0) come region number
    region_number = block_trip[0]

    # Formattta l'output
    # Il numero della carta viene composto concatenando il prefisso e il postfix.
    # Il postfix viene stampato come un numero a 15 cifre con zeri iniziali.
    output = (
        "Zolotaya korona\n"
        f"Card number: {card_number_prefix}{card_number_postfix:015d}\n"
        f"Tariff: {tariff // 256:02X}.{tariff % 256:02X}: {tariff_name}\n"
        f"Region: {region_number}\n"
    )
    return output

def main():
    if len(sys.argv) != 2:
        print("Usage: python zolotaya_korona_online.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            dump = f.read()
        result = zolotaya_korona_online_parse(dump)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
