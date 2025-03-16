#!/usr/bin/env python3
import sys
import struct

BLOCK_SIZE = 16

def get_block(data: bytes, block_num: int) -> bytes:
    """Restituisce il blocco (16 byte) dal dump."""
    start = block_num * BLOCK_SIZE
    return data[start:start + BLOCK_SIZE]

def bytes_to_int_be(b: bytes) -> int:
    """Converte i byte in un intero (big-endian)."""
    return int.from_bytes(b, byteorder='big')

def parse_datetime(date_val: int) -> (bool, str):
    """
    Converte un valore a 16 bit in una data.
    Formato: anno = 2000 + (date >> 9), mese = (date >> 5) & 0x0F, giorno = date & 0x1F.
    Restituisce (valid, formatted_date)
    """
    if date_val == 0:
        return (False, "")
    year = 2000 + (date_val >> 9)
    month = (date_val >> 5) & 0x0F
    day = date_val & 0x1F
    return (True, f"{year:04d}-{month:02d}-{day:02d}")

def umarsh_parse(dump: bytes) -> str:
    # Assumiamo dump completo di una Mifare Classic 1K (256 byte, 16 blocchi per settore, 16 settori)
    # Settore interessato: 8. Per 1K, la funzione mf_classic_get_first_block_num_of_sector(ticket_sector)
    # equivale a ticket_sector * 4.
    ticket_sector = 8
    ticket_sector_start = ticket_sector * 4  # blocco 32

    # Header: dal blocco ticket_sector_start (blocco 32)
    header_block = get_block(dump, ticket_sector_start)
    header_part_0 = bytes_to_int_be(header_block[0:4])
    header_part_1 = bytes_to_int_be(header_block[4:8])
    if (header_part_0 + header_part_1) != 0xFFFFFFFF:
        return "Error: invalid header in ticket sector."

    # Blocco 1 (blocco 33)
    block1 = get_block(dump, ticket_sector_start + 1)
    expiry_date = bytes_to_int_be(block1[1:3])
    # region_number: ((block1[8] >> 5) & 0x07) << 4  ORed con (block1[12] & 0x0F)
    region_number = (((block1[8] >> 5) & 0x07) << 4) | (block1[12] & 0x0F)
    refill_counter = block1[7]
    card_number = bytes_to_int_be(block1[8:12]) & 0x3FFFFFFF
    if card_number == 0:
        return "Error: card number is 0."

    # Blocco 2 (blocco 34)
    block2 = get_block(dump, ticket_sector_start + 2)
    valid_to = bytes_to_int_be(block2[0:2])
    terminal_number = bytes_to_int_be(block2[3:6])
    last_refill_date = bytes_to_int_be(block2[6:8])
    balance_rub = bytes_to_int_be(block2[8:10]) & 0x7FFF
    balance_kop = block2[10] & 0x7F

    valid_expiry, expiry_str = parse_datetime(expiry_date)
    valid_valid_to, valid_to_str = parse_datetime(valid_to)
    valid_last_refill, last_refill_str = parse_datetime(last_refill_date)

    output_lines = []
    output_lines.append("Umarsh")
    output_lines.append(f"Card number: {card_number}")
    output_lines.append(f"Region: {region_number:02d}")
    output_lines.append(f"Terminal number: {terminal_number}")
    output_lines.append(f"Refill counter: {refill_counter}")
    output_lines.append(f"Balance: {balance_rub}.{balance_kop:02d} RUR")
    if valid_expiry:
        output_lines.append(f"Expires: {expiry_str}")
    if valid_valid_to:
        output_lines.append(f"Valid to: {valid_to_str}")
    if valid_last_refill:
        output_lines.append(f"Last refill: {last_refill_str}")

    return "\n".join(output_lines)

def main():
    if len(sys.argv) != 2:
        print("Usage: python umarsh.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            dump = f.read()
        result = umarsh_parse(dump)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
