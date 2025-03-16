#!/usr/bin/env python3
from datetime import datetime

def bcd_to_int(b):
    """Converte un valore BCD (0-255) in un intero."""
    return ((b >> 4) & 0xF) * 10 + (b & 0xF)

def format_date(day, month, year, fmt='DMY'):
    """
    Formattta una data. Se il giorno non è presente (day==0),
    restituisce solo mese e anno, altrimenti giorno, mese e anno.
    Per il formato DMY il separatore usato è il punto.
    """
    if day:
        return f"{day:02d}.{month:02d}.{year:04d}"
    else:
        return f"{month:02d}.{year:04d}"

# Mapping di esempio per i nomi di paese e valuta
COUNTRY_NAMES = {
    840: "United States",  # USA
    # Altri codici possono essere aggiunti
}
CURRENCY_NAMES = {
    840: "USD",
    # Altri codici possono essere aggiunti
}

def get_country_name(code):
    """Restituisce il nome del paese dato un codice numerico."""
    return COUNTRY_NAMES.get(code, f"Unknown (code {code})") if code else None

def get_currency_name(code):
    """Restituisce il nome della valuta dato un codice numerico."""
    return CURRENCY_NAMES.get(code, f"Unknown (code {code})") if code else None

def parse_emv_card(emv_app):
    """
    Esegue il parsing dei dati EMV forniti in un dizionario (emv_app) e restituisce
    una stringa contenente le informazioni estratte.
    
    I campi attesi sono:
      - application_label, application_name
      - pan (bytes) e pan_len (numero di byte validi nel PAN)
      - cardholder_name
      - effective_day, effective_month, effective_year (in formato BCD)
      - exp_day, exp_month, exp_year (in formato BCD)
      - country_code, currency_code
      - pin_try_counter
      - application_interchange_profile (lista di almeno 2 byte)
    """
    output_lines = []
    parsed = False

    # Titolo: usa application_label se presente, altrimenti application_name, altrimenti "EMV"
    if emv_app.get("application_label"):
        output_lines.append(f"{emv_app['application_label']}")
    elif emv_app.get("application_name"):
        output_lines.append(f"{emv_app['application_name']}")
    else:
        output_lines.append("EMV")

    # PAN: se pan_len è non zero, formatta il PAN estraendo coppie di byte in esadecimale
    if emv_app.get("pan_len", 0):
        pan_bytes = emv_app.get("pan")
        pan_len = emv_app.get("pan_len")
        pan_str = ""
        for i in range(0, pan_len, 2):
            if i+1 < pan_len:
                pan_str += f"{pan_bytes[i]:02X}{pan_bytes[i+1]:02X} "
            else:
                pan_str += f"{pan_bytes[i]:02X} "
        # Rimuove eventuale padding 'F' alla fine
        pan_str = pan_str.rstrip().rstrip("F")
        output_lines.append(pan_str)
        parsed = True

    # Nome del titolare della carta
    if emv_app.get("cardholder_name"):
        output_lines.append(f"Cardholder name: {emv_app['cardholder_name']}")
        parsed = True

    # Date di validità: effective e expiration
    # Se i campi relativi al mese sono presenti, li convertiamo da BCD
    if emv_app.get("effective_month", 0):
        eff_day = bcd_to_int(emv_app.get("effective_day", 0)) if emv_app.get("effective_day") else 0
        eff_month = bcd_to_int(emv_app["effective_month"])
        eff_year = 2000 + bcd_to_int(emv_app.get("effective_year", 0))
        effective_date = format_date(eff_day, eff_month, eff_year)
        output_lines.append(f"Effective: {effective_date}")
        parsed = True

    if emv_app.get("exp_month", 0):
        exp_day = bcd_to_int(emv_app.get("exp_day", 0)) if emv_app.get("exp_day") else 0
        exp_month = bcd_to_int(emv_app["exp_month"])
        exp_year = 2000 + bcd_to_int(emv_app.get("exp_year", 0))
        expiration_date = format_date(exp_day, exp_month, exp_year)
        output_lines.append(f"Expires: {expiration_date}")
        parsed = True

    # Nome del paese
    country_code = emv_app.get("country_code", 0)
    country_name = get_country_name(country_code)
    if country_name:
        output_lines.append(f"Country: {country_name}")
        parsed = True

    # Nome della valuta
    currency_code = emv_app.get("currency_code", 0)
    currency_name = get_currency_name(currency_code)
    if currency_name:
        output_lines.append(f"Currency: {currency_name}")
        parsed = True

    # Contatore dei tentativi PIN (se diverso da 0xFF)
    pin_try_counter = emv_app.get("pin_try_counter", 0xFF)
    if pin_try_counter != 0xFF:
        output_lines.append(f"PIN attempts left: {pin_try_counter}")
        parsed = True

    # Verifica se l'applicazione indica che la carta è mobile
    aip = emv_app.get("application_interchange_profile", [])
    if len(aip) >= 2 and ((aip[1] >> 6) & 0b1):
        output_lines.append("Mobile: yes")
        parsed = True

    if not parsed:
        output_lines.append("No data was parsed")

    return "\n".join(output_lines)

# Esempio di utilizzo:
if __name__ == '__main__':
    # Esempio fittizio per simulare i dati di un'applicazione EMV
    emv_app_example = {
        "application_label": "VISA Debit",
        "application_name": "",
        # Il PAN è rappresentato come bytes; ad es. 8 byte
        "pan": bytes([0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x12, 0x34]),
        "pan_len": 8,
        "cardholder_name": "JOHN DOE",
        "effective_day": 0x01,   # BCD per 1
        "effective_month": 0x02, # BCD per 2
        "effective_year": 0x21,  # BCD per 21 => 2021
        "exp_day": 0x31,         # BCD per 31
        "exp_month": 0x12,       # BCD per 12
        "exp_year": 0x25,        # BCD per 25 => 2025
        "country_code": 840,     # USA
        "currency_code": 840,    # USD
        "pin_try_counter": 3,
        "application_interchange_profile": [0x00, 0x40]  # Il secondo byte, 0x40, >>6 == 1
    }
    
    result = parse_emv_card(emv_app_example)
    print(result)
