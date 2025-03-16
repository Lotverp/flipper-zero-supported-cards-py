#!/usr/bin/env python3
import sys

def read_page(dump: bytes, page: int) -> bytes:
    """Restituisce i 4 byte del blocco 'page' dal dump."""
    start = page * 4
    return dump[start:start+4]

def sonicare_get_head_type(dump: bytes) -> str:
    """Determina il tipo di head basandosi sul primo byte della pagina 34.
       Se è 0x30, viene considerata "White", altrimenti "Unknown".  
       (Non abbiamo dati sufficienti per distinguere un eventuale "Black".)
    """
    page34 = read_page(dump, 34)
    return "White" if page34[0] == 0x30 else "Unknown"

def sonicare_get_seconds_brushed(dump: bytes) -> int:
    """Estrae il numero di secondi spazzolati dalla pagina 36.
       I 2 byte (al byte 0 e 1) vengono interpretati in little-endian.
    """
    page36 = read_page(dump, 36)
    return page36[0] + (page36[1] << 8)

def sonicare_parse(dump: bytes) -> str:
    # Verifica il link NDEF: a partire dal byte (5*4 + 3) il dump deve contenere la stringa test
    test = b"philips.com/nfcbrushheadtap"
    offset = 5 * 4 + 3
    if dump[offset: offset + len(test)] != test:
        return "Not a Philips Sonicare head"
    
    head_type = sonicare_get_head_type(dump)
    seconds_brushed = sonicare_get_seconds_brushed(dump)
    hours = seconds_brushed // 3600
    minutes = (seconds_brushed // 60) % 60
    seconds = seconds_brushed % 60

    output = (
        "Philips Sonicare head\n"
        f"Color: {head_type}\n"
        f"Time brushed: {hours:02d}:{minutes:02d}:{seconds:02d}\n"
    )
    return output

def main():
    if len(sys.argv) != 2:
        print("Usage: python sonicare.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            dump = f.read()
        result = sonicare_parse(dump)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
