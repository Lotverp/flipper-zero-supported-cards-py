#!/usr/bin/env python3
import sys

# Costanti
LATEST_SALE_MARKER = 0x02
SALE_RECORD_TIME_STAMP_A = 0x0C  # pagina 12
SALE_RECORD_TIME_STAMP_B = 0x0E  # pagina 14
FULL_SALE_TIME_STAMP_PAGE = 0x09  # pagina 9
BALANCE_PAGE = 0x08              # pagina 8
SALE_YEAR_OFFSET = 2000
PAGE_SIZE = 4  # 4 byte per pagina

def get_pages(data: bytes):
    """Divide il dump in pagine da 4 byte."""
    return [data[i:i+PAGE_SIZE] for i in range(0, len(data), PAGE_SIZE)]

def get_bits(data: bytes, bit_offset: int, bit_length: int) -> int:
    """
    Estrae 'bit_length' bit da 'data' (big-endian) a partire dal 'bit_offset'.
    """
    total_bits = len(data) * 8
    if bit_offset + bit_length > total_bits:
        raise ValueError("Out of bounds in get_bits")
    value = int.from_bytes(data, byteorder='big')
    shift = total_bits - (bit_offset + bit_length)
    return (value >> shift) & ((1 << bit_length) - 1)

def trt_parse(dump: bytes) -> str:
    pages = get_pages(dump)
    
    # Verifica la presenza del marker in pagina 12 o 14
    latest_sale_page = 0
    if pages[SALE_RECORD_TIME_STAMP_A][0] == LATEST_SALE_MARKER:
        latest_sale_page = SALE_RECORD_TIME_STAMP_A
    elif pages[SALE_RECORD_TIME_STAMP_B][0] == LATEST_SALE_MARKER:
        latest_sale_page = SALE_RECORD_TIME_STAMP_B
    else:
        return "Error: sale record marker not found."

    # Ottieni il record parziale dalla pagina precedente
    partial_record = pages[latest_sale_page - 1]
    # Estrai 20 bit a partire dal bit 3 del record parziale
    latest_sale_record = get_bits(partial_record, 3, 20)
    
    # Ottieni il record completo dalla pagina FULL_SALE_TIME_STAMP_PAGE (pagina 9)
    full_record = pages[FULL_SALE_TIME_STAMP_PAGE]
    latest_sale_full_record = get_bits(full_record, 0, 27)
    
    if latest_sale_record != (latest_sale_full_record & 0xFFFFF):
        return "Error: sale record copy mismatch."
    if latest_sale_record == 0 or latest_sale_full_record == 0:
        return "Error: sale record is zero."
    
    # Decodifica la data dal record completo (27 bit)
    # Formato: yyy yyyymmmm dddddhhh hhnnnnnn
    sale_year = ((latest_sale_full_record & 0x7F00000) >> 20) + SALE_YEAR_OFFSET
    sale_month = (latest_sale_full_record & 0xF0000) >> 16
    sale_day = (latest_sale_full_record & 0xF800) >> 11
    sale_hour = (latest_sale_full_record & 0x7C0) >> 6
    sale_minute = latest_sale_full_record & 0x3F
    
    # Estrai il saldo dalla pagina BALANCE_PAGE (pagina 8)
    balance_page = pages[BALANCE_PAGE]
    # Legge 16 bit a partire dal byte 2
    balance = int.from_bytes(balance_page[2:4], byteorder='big')
    balance_yuan = balance // 100
    balance_cent = balance % 100
    
    # Costruisci l'output
    output = []
    output.append("TRT Tianjin Metro")
    output.append("Single-Use Ticket")
    output.append(f"Balance: {balance_yuan}.{balance_cent:02d} RMB")
    output.append(f"Sale Date: ")
    output.append(f"{sale_year:04d}-{sale_month:02d}-{sale_day:02d} {sale_hour:02d}:{sale_minute:02d}")
    
    return "\n".join(output)

def main():
    if len(sys.argv) != 2:
        print("Usage: python trt.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            dump = f.read()
        result = trt_parse(dump)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
