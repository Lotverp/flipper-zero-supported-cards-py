#!/usr/bin/env python3
import sys
from datetime import datetime

# Costanti ITSO
ITSO_APP_ID = bytes([0x16, 0x02, 0xA0])
ITSO_FILE_ID = 0x0F  # non usato direttamente in questa conversione

# Funzione per byteswap a 64 bit (swap_uint64)
def swap_uint64(val: int) -> int:
    # Converte l'intero in 8 byte, inverte l'ordine e ricostruisce l'intero
    b = val.to_bytes(8, byteorder='big')
    return int.from_bytes(b[::-1], byteorder='big')

# Legge 32 byte dal dump e li interpreta come la struttura ItsoFile:
# struct ItsoFile { uint64_t part1, part2, part3, part4; };
def read_itso_file(data: bytes):
    if len(data) < 32:
        raise ValueError("Dati ITSO insufficienti (minimo 32 byte richiesti).")
    part1 = int.from_bytes(data[0:8], byteorder='big')
    part2 = int.from_bytes(data[8:16], byteorder='big')
    # part3 e part4 non sono usati
    return part1, part2

def itso_parse(file_data: bytes) -> str:
    # Legge i primi 32 byte come file ITSO
    try:
        part1, part2 = read_itso_file(file_data)
    except ValueError as e:
        return f"Errore: {e}"
    
    # Applica byteswap alle prime due parti
    x1 = swap_uint64(part1)
    x2 = swap_uint64(part2)
    
    # Formatta cardBuff come concatenazione di x1 e x2 in esadecimale con zero-padding a 16 cifre ciascuno (32 caratteri totali)
    cardBuff = f"{x1:016x}{x2:016x}"
    # dateBuff è la rappresentazione esadecimale di x2 (16 caratteri)
    dateBuff = f"{x2:016x}"
    
    # Salta i primi 4 caratteri di cardBuff e prendi i successivi 18 caratteri
    cardp = cardBuff[4:4+18]  # equivalente a cardBuff[4:22]
    if not cardp.startswith("633597"):
        return "Errore: prefisso della carta non valido."
    
    # Per la data, prendi da dateBuff a partire dall'indice 12 (5 caratteri)
    datep = dateBuff[12:12+5]
    try:
        dateStamp = int(datep, 16)
    except ValueError:
        return "Errore: conversione della data fallita."
    
    # Calcola il timestamp Unix: dateStamp rappresenta il numero di giorni passati dal 01/01/1997,
    # e 01/01/1997 in Unix è 852076800.
    unixTimestamp = dateStamp * 86400 + 852076800
    
    # Format della data di scadenza
    expiry_date = datetime.utcfromtimestamp(unixTimestamp).strftime("%Y-%m-%d")
    
    # Format della carta: suddivide cardp in gruppi secondo l'array digit_count = [6, 4, 4, 4]
    digit_count = [6, 4, 4, 4]
    formatted_card = ""
    k = 0
    for count in digit_count:
        formatted_card += cardp[k:k+count] + " "
        k += count
    formatted_card = formatted_card.strip()
    
    # Componi l'output finale
    output = f"ITSO Card\n{formatted_card}\nExpiry: {expiry_date}"
    return output

def main():
    if len(sys.argv) != 2:
        print("Uso: python itso.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            file_data = f.read()
        result = itso_parse(file_data)
        print(result)
    except Exception as e:
        print("Errore:", e)

if __name__ == '__main__':
    main()
