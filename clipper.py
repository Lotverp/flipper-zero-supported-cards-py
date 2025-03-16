#!/usr/bin/env python3
import struct
from datetime import datetime, timedelta

# ============================================
# Mapping e costanti (da clipper.c)
# ============================================

# Tipi di applicazioni osservati (per semplicità assumiamo il primo tipo: "Card")
clipper_types = {
    (0x90, 0x11, 0xf2): "Card",
    (0x91, 0x11, 0xf2): "Mobile Device"
}

# Identificatori di agenzie di trasporto
agency_names = {
    0x0001: "AC Transit",
    0x0004: "BART",
    0x0006: "Caltrain",
    0x0008: "CCTA",
    0x000b: "GGT",
    0x000f: "SamTrans",
    0x0011: "VTA",
    0x0012: "Muni",
    0x0019: "GG Ferry",
    0x001b: "SF Bay Ferry"
}

# Zone per BART (parziale)
bart_zones = {
    0x0001: "Colma",
    0x0002: "Daly City",
    0x0003: "Balboa Park",
    0x0004: "Glen Park",
    0x0005: "24th St Mission",
    0x0006: "16th St Mission",
    0x0007: "Civic Center/UN Plaza",
    0x0008: "Powell St",
    0x0009: "Montgomery St",
    0x000a: "Embarcadero",
    0x000b: "West Oakland",
    0x000c: "12th St/Oakland City Center",
    0x000d: "19th St/Oakland",
    0x000e: "MacArthur",
    0x000f: "Rockridge",
    0x0010: "Orinda",
    0x0011: "Lafayette",
    0x0012: "Walnut Creek",
    0x0013: "Pleasant Hill/Contra Costa Centre",
    0x0014: "Concord",
    0x0015: "North Concord/Martinez",
    0x0016: "Pittsburg/Bay Point",
    0x0017: "Ashby",
    0x0018: "Downtown Berkeley",
    0x0019: "North Berkeley",
    0x001a: "El Cerrito Plaza",
    0x001b: "El Cerrito Del Norte",
    0x001c: "Richmond",
    0x001d: "Lake Merrit",
    0x001e: "Fruitvale",
    0x001f: "Coliseum",
    0x0020: "San Leandro",
    0x0021: "Bay Fair",
    0x0022: "Hayward",
    0x0023: "South Hayward",
    0x0024: "Union City",
    0x0025: "Fremont",
    0x0026: "Castro Valley",
    0x0027: "Dublin/Pleasanton",
    0x0028: "South San Francisco",
    0x0029: "San Bruno",
    0x002a: "SFO Airport",
    0x002b: "Millbrae",
    0x002c: "West Dublin/Pleasanton",
    0x002d: "OAK Airport",
    0x002e: "Warm Springs/South Fremont",
    0x002f: "Milpitas",
    0x0030: "Berryessa/North San Jose",
}

# Zone per MUNI (parziale)
muni_zones = {
    0x0000: "City Street",
    0x0005: "Embarcadero",
    0x0006: "Montgomery",
    0x0007: "Powell",
    0x0008: "Civic Center",
    0x0009: "Van Ness",
    0x000a: "Church",
    0x000b: "Castro",
    0x000c: "Forest Hill",
    0x000d: "West Portal",
    0x0019: "Union Square/Market Street",
    0x001a: "Chinatown - Rose Pak",
    0x001b: "Yerba Buena/Moscone"
}

# Zone per AC Transit (parziale)
actransit_zones = {
    0x0000: "City Street"
}

# Zone per Caltrain (parziale)
caltrain_zones = {
    0x0001: "Zone 1",
    0x0002: "Zone 2",
    0x0003: "Zone 3",
    0x0004: "Zone 4",
    0x0005: "Zone 5",
    0x0006: "Zone 6"
}

# Mappa agenzia -> zone (utilizzata per ottenere il nome della zona)
agency_zone_map = {
    0x0001: actransit_zones,
    0x0004: bart_zones,
    0x0006: caltrain_zones,
    0x0012: muni_zones
}

# Identificativi dei file (come definiti in clipper.c)
FILE_ID_IDENTITY = 8      # File identità
FILE_ID_ECASH    = 2      # File cash
FILE_ID_HISTIDX  = 6      # File indice cronologia
FILE_ID_HISTORY  = 14     # File cronologia

# ============================================
# Funzioni helper per l'interpretazione dei dati
# ============================================

def get_u32be(data: bytes, offset: int = 0) -> int:
    return int.from_bytes(data[offset:offset+4], byteorder='big')

def get_u16be(data: bytes, offset: int = 0) -> int:
    return int.from_bytes(data[offset:offset+2], byteorder='big')

def get_i16be(data: bytes, offset: int = 0) -> int:
    val = get_u16be(data, offset)
    return val - 0x10000 if val > 0x7FFF else val

def decode_usd(amount_cents: int):
    """Divide un importo in centesimi in dollari e centesimi, gestendo eventuali segni."""
    usd = amount_cents // 100
    cents = abs(amount_cents) % 100
    is_negative = amount_cents < 0
    return usd, cents, is_negative

def timestamp_from_1900(tmst: int) -> datetime:
    """Converte un timestamp in secondi dal 1900-01-01 in datetime."""
    base = datetime(1900, 1, 1)
    return base + timedelta(seconds=tmst)

def format_timestamp(tmst: int) -> str:
    dt_obj = timestamp_from_1900(tmst)
    return dt_obj.strftime("%d/%m/%Y %H:%M:%S") + " (UTC)"

# ============================================
# Parsing dei file della Clipper card
# ============================================

def decode_id_file(ef8_data: bytes) -> dict:
    """
    Decodifica il file d'identità (file id 8).
    Il campo card_id è nei byte 1-4 (big-endian).
    """
    info = {}
    if len(ef8_data) < 5:
        raise ValueError("Dati file identità insufficienti")
    info["serial_number"] = int.from_bytes(ef8_data[1:5], byteorder='big')
    return info

def decode_cash_file(ef2_data: bytes, info: dict):
    """
    Decodifica il file cash (file id 2) e aggiorna info con:
      - counter (U16BE) a offset 2
      - last_updated_tm_1900 (U32BE) a offset 4
      - last_terminal_id (U16BE) a offset 8
      - last_txn_id (U16BE) a offset 0x10
      - balance_cents (S16BE) a offset 0x12
    """
    if len(ef2_data) < 0x14:
        raise ValueError("Dati file cash insufficienti")
    info["counter"] = get_u16be(ef2_data, 2)
    info["last_updated_tm_1900"] = get_u32be(ef2_data, 4)
    info["last_terminal_id"] = get_u16be(ef2_data, 8)
    info["last_txn_id"] = get_u16be(ef2_data, 0x10)
    info["balance_cents"] = get_i16be(ef2_data, 0x12)

def dump_ride_event(record: bytes) -> str:
    """
    Decodifica un singolo record di corsa (32 byte, file cronologia).
    Restituisce una stringa formattata con i dati della corsa oppure una stringa vuota
    se il record non è valido.
    """
    if len(record) < 0x18 or record[0] != 0x10:
        return ""
    
    agency_id = get_u16be(record, 2)
    if agency_id == 0:
        return ""
    agency_name = agency_names.get(agency_id, "Unknown")
    vehicle_id = get_u16be(record, 0x0a)
    fare_raw = get_i16be(record, 6)
    fare_usd, fare_cents, _ = decode_usd(fare_raw)
    time_on = get_u32be(record, 0x0c)
    time_off = get_u32be(record, 0x10)
    zone_id_on = get_u16be(record, 0x14)
    zone_id_off = get_u16be(record, 0x16)
    
    # Ottieni il nome della zona in base all'agenzia
    zone_on = "Unknown"
    zone_off = "Unknown"
    zone_map = agency_zone_map.get(agency_id, {})
    zone_on = zone_map.get(zone_id_on, "Unknown")
    zone_off = zone_map.get(zone_id_off, "Unknown")
    
    out = []
    out.append("----- Ride Record -----")
    out.append(f"Date & Time On: {format_timestamp(time_on)}")
    out.append(f"Fare: ${fare_usd}.{fare_cents:02d}")
    out.append(f"Agency: {agency_name} (0x{agency_id:04x})")
    out.append(f"Boarding Zone: {zone_on} (0x{zone_id_on:04x})")
    if vehicle_id != 0:
        out.append(f"Vehicle id: {vehicle_id}")
    if time_off != 0:
        out.append(f"Alighting Zone: {zone_off} (0x{zone_id_off:04x})")
        out.append(f"Date & Time Off: {format_timestamp(time_off)}")
    return "\n".join(out)

def dump_ride_history(hist_idx_data: bytes, hist_data: bytes) -> str:
    """
    Decodifica la cronologia delle corse.
    Il file indice (hist_idx) contiene 16 byte; per ogni byte, se non 0xff,
    il valore indica il numero del record da cercare nel file cronologia (record size = 32 byte).
    """
    records = []
    kRideRecordSize = 32
    for i in range(min(16, len(hist_idx_data))):
        record_num = hist_idx_data[i]
        if record_num == 0xff:
            break
        record_offset = record_num * kRideRecordSize
        if record_offset + kRideRecordSize > len(hist_data):
            break
        record = hist_data[record_offset:record_offset+kRideRecordSize]
        event_str = dump_ride_event(record)
        if event_str:
            records.append(event_str)
    return "\n\n".join(records)

# ============================================
# Funzione principale di parsing della Clipper card
# ============================================

def parse_clipper_card(id_data: bytes, cash_data: bytes, hist_idx_data: bytes, hist_data: bytes) -> str:
    """
    Esegue il parsing dei file della Clipper card e restituisce una stringa con i dati estratti.
    """
    output = []
    
    # Selezioniamo il tipo di carta: per semplicità assumiamo "Card"
    card_type = clipper_types.get((0x90, 0x11, 0xf2), "Unknown")
    
    # Decodifica file identità
    info = decode_id_file(id_data)
    
    # Decodifica file cash e aggiorna info
    decode_cash_file(cash_data, info)
    
    balance_usd, balance_cents, _ = decode_usd(info["balance_cents"])
    
    output.append("----- Clipper Card -----")
    output.append(f"Serial: {info['serial_number']}")
    output.append(f"Balance: ${balance_usd}.{balance_cents:02d}")
    output.append(f"Type: {card_type}")
    output.append("----- Last Update -----")
    if info["last_updated_tm_1900"] != 0:
        output.append(f"Date & Time: {format_timestamp(info['last_updated_tm_1900'])}")
    else:
        output.append("Never")
    output.append(f"Terminal: 0x{info['last_terminal_id']:04x}")
    output.append(f"Transaction Id: {info['last_txn_id']}")
    output.append(f"Counter: {info['counter']}")
    
    # Cronologia delle corse
    output.append("\n----- Ride History -----")
    ride_history = dump_ride_history(hist_idx_data, hist_data)
    if ride_history:
        output.append(ride_history)
    else:
        output.append("Nessuna corsa registrata.")
    
    return "\n".join(output)

# ============================================
# Esempio di utilizzo
# ============================================

if __name__ == '__main__':
    try:
        with open("clipper_id.bin", "rb") as f:
            id_data = f.read()
        with open("clipper_cash.bin", "rb") as f:
            cash_data = f.read()
        with open("clipper_histidx.bin", "rb") as f:
            hist_idx_data = f.read()
        with open("clipper_history.bin", "rb") as f:
            hist_data = f.read()
        
        result = parse_clipper_card(id_data, cash_data, hist_idx_data, hist_data)
        print(result)
    except FileNotFoundError as e:
        print("Errore: file non trovato. Verifica di avere i file clipper_id.bin, clipper_cash.bin, clipper_histidx.bin e clipper_history.bin.")
