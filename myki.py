#!/usr/bin/env python3
import sys

def myki_calculate_luhn(number: int) -> int:
    """
    Calcola il check digit Luhn per il numero della carta.
    Si scarta l'eventuale cifra di controllo esistente (payload = number // 10),
    quindi si applica l'algoritmo Luhn e si restituisce il check digit.
    """
    payload = number // 10
    total_sum = 0
    position = 0
    while payload > 0:
        digit = payload % 10
        if position % 2 == 0:
            digit *= 2
        if digit > 9:
            digit = (digit // 10) + (digit % 10)
        total_sum += digit
        payload //= 10
        position += 1
    return (10 - (total_sum % 10)) % 10

def parse_myki_file(file_data: bytes) -> str:
    """
    Esegue il parsing dei dati di una myki card.
    Il file_data deve contenere almeno 8 byte:
      - I primi 4 byte (big-endian) rappresentano myki_file.top
      - I successivi 4 byte (big-endian) rappresentano myki_file.bottom
    Il numero di carta viene calcolato come:
      card_number = top * 1000000000 + bottom * 10 + check_digit
    dove il check_digit viene calcolato con l'algoritmo di Luhn sul numero senza la cifra di controllo.
    Infine il numero viene suddiviso in gruppi secondo l'array digit_count = [1, 5, 4, 4, 1].
    """
    if len(file_data) < 8:
        return "Error: File too short for Myki data."
    
    # Legge i primi 4 byte come myki_file.top (big-endian)
    top = int.from_bytes(file_data[0:4], byteorder='big')
    # Legge i successivi 4 byte come myki_file.bottom (big-endian)
    bottom = int.from_bytes(file_data[4:8], byteorder='big')
    
    # Verifica: il campo top deve essere esattamente 308425
    if top != 308425:
        return "Error: Top field does not equal 308425."
    # Il campo bottom deve essere un numero a 8 cifre
    if bottom < 10000000 or bottom >= 100000000:
        return "Error: Bottom field is out of range."
    
    # Calcola il numero base: top * 1000000000 + bottom * 10
    card_number = top * 1000000000 + bottom * 10
    # Aggiunge il check digit calcolato con Luhn
    check_digit = myki_calculate_luhn(card_number)
    card_number += check_digit

    # Converti il numero della carta in stringa
    card_string = f"{card_number}"
    # Il numero di carta deve essere lungo 15 cifre; se necessario, aggiungi zeri iniziali
    card_string = card_string.zfill(15)
    
    # Gruppi di cifre: [1, 5, 4, 4, 1]
    digit_groups = [1, 5, 4, 4, 1]
    groups = []
    index = 0
    for count in digit_groups:
        groups.append(card_string[index:index+count])
        index += count
    formatted_card = " ".join(groups)
    
    output = "\e#myki\nNo.: " + formatted_card
    return output

def main():
    if len(sys.argv) != 2:
        print("Usage: python myki.py <dump_file>")
        sys.exit(1)
    dump_file = sys.argv[1]
    try:
        with open(dump_file, "rb") as f:
            file_data = f.read()
        result = parse_myki_file(file_data)
        print(result)
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
