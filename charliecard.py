#!/usr/bin/env python3
import struct
from datetime import datetime, timedelta

# Costanti tipiche dalla versione C
CHARLIE_EPOCH = datetime(2003, 1, 1, 0, 0, 0)
CHARLIE_TIME_DELTA_SECS = 60           # 1 minuto
CHARLIE_END_VALID_DELTA_SECS = 60 * 8    # 8 minuti

CHARLIE_N_TRANSACTION_HISTORY = 10
CHARLIE_N_PASSES = 4

# Mappature (parziali – completa se necessario)
charliecard_types = {
    367: "Adult",
    366: "SV Adult",
    418: "Student",
    419: "Senior",
    420: "TAP",
    417: "Blind",
    426: "Child",
    410: "Employee ID Without Passback",
    414: "Employee ID With Passback",
    415: "Retiree",
    416: "Police/Fire",
    135: "30 Day Local Bus Pass",
    136: "30 Day Inner Express Bus Pass",
    137: "30 Day Outer Express Bus Pass",
    138: "30 Day LinkPass",
    139: "30 Day Senior LinkPass",
    148: "30 Day TAP LinkPass",
    150: "Monthly Student LinkPass",
    424: "Monthly TAP LinkPass",
    425: "Monthly Senior LinkPass",
    421: "Senior TAP/Permit",
    422: "Senior TAP/Permit 30 Days",
    # ... (altri mapping come nella versione C)
}

fare_gate_ids = {
    6766: "Davis",
    6767: "Davis",
    6768: "Davis",
    6769: "Davis",
    6770: "Davis",
    6771: "Davis",
    6772: "Davis",
    2167: "Davis",
    7020: "Davis",
    6781: "Porter",
    6780: "Porter",
    6779: "Porter",
    6778: "Porter",
    6777: "Porter",
    6776: "Porter",
    6775: "Porter",
    2168: "Porter",
    7021: "Porter",
    6782: "Porter",
    # ... (completa con tutti gli ID se necessario)
}


# Helper per calcolare l'offset dato settore, blocco e byte
def get_block_offset(sector: int) -> int:
    # Per una Mifare Classic 1K: 4 blocchi per settore, 16 byte per blocco
    return sector * 4 * 16

# Legge "length" byte da card_data a partire da settore, blocco e byte offset,
# interpretandoli in big-endian
def pos_to_num(card_data: bytes, sector: int, block: int, byte: int, length: int) -> int:
    offset = get_block_offset(sector) + block * 16 + byte
    return int.from_bytes(card_data[offset:offset+length], byteorder='big')

# Funzione per il parsing di un importo (money)
def money_parse(card_data: bytes, sector: int, block: int, byte: int):
    raw_val = pos_to_num(card_data, sector, block, byte, 2)
    # I valori sono in "half-cents": togliamo il bit di segno/flag e dividiamo per 2
    amt = (raw_val & 0x7FFF) >> 1
    dollars = amt // 100
    cents = amt % 100
    return dollars, cents

# Parsing della data: 3 byte rappresentano minuti da CHARLIE_EPOCH
def date_parse(card_data: bytes, sector: int, block: int, byte: int) -> datetime:
    ts_charlie = pos_to_num(card_data, sector, block, byte, 3)
    return CHARLIE_EPOCH + timedelta(seconds=ts_charlie * CHARLIE_TIME_DELTA_SECS)

# Parsing del campo "end validity" (scadenza)
def end_validity_parse(card_data: bytes, sector: int, block: int, byte: int) -> datetime:
    ts_charlie_ev = pos_to_num(card_data, sector, block, byte, 3) & 0x1FFFFF
    return CHARLIE_EPOCH + timedelta(seconds=ts_charlie_ev * CHARLIE_END_VALID_DELTA_SECS)

# Parsing del settore del produttore per ottenere il numero di carta (UID)
def mfg_sector_parse(card_data: bytes) -> int:
    # In questo esempio ipotizziamo che i primi 4 byte del dump contengano l'UID
    uid = card_data[0:4]
    return int.from_bytes(uid, byteorder='big')

# Parsing del settore dei contatori (settore 1)
def counter_sector_parse(card_data: bytes):
    n_uses1 = pos_to_num(card_data, 1, 1, 0, 2)
    n_uses2 = pos_to_num(card_data, 1, 2, 0, 2)
    if n_uses1 <= n_uses2:
        active_sector = 2
        n_uses = n_uses1 - 1
    else:
        active_sector = 3
        n_uses = n_uses2 - 1
    return n_uses, active_sector

# Parsing del settore del bilancio (settore attivo 2 o 3)
def balance_sector_parse(card_data: bytes, active_sector: int):
    issued = date_parse(card_data, active_sector, 0, 6)
    end_validity = end_validity_parse(card_data, active_sector, 1, 1)
    type_val = pos_to_num(card_data, active_sector, 1, 0, 2) >> 6
    balance = money_parse(card_data, active_sector, 1, 5)
    return {
        "issued": issued,
        "end_validity": end_validity,
        "type": type_val,
        "balance": balance
    }

# Parsing di una transazione individuale
def transaction_parse(card_data: bytes, sector: int, block: int, byte: int):
    t_date = date_parse(card_data, sector, block, byte)
    tmp = pos_to_num(card_data, sector, block, byte+3, 2)
    gate = tmp >> 3
    g_flag = tmp & 0b111
    fare = money_parse(card_data, sector, block, byte+5)
    f_flag = pos_to_num(card_data, sector, block, byte+5, 2) & 0x8001
    return {
        "date": t_date,
        "gate": gate,
        "g_flag": g_flag,
        "fare": fare,
        "f_flag": f_flag
    }

# Parsing della cronologia delle transazioni (settori 6-7)
def transactions_parse(card_data: bytes):
    transactions = []
    for i in range(CHARLIE_N_TRANSACTION_HISTORY):
        sector = 6 + (i // 6)  # I primi 6 in settore 6, i restanti in settore 7
        block = (i // 2) % 3
        byte = (i % 2) * 7
        t = transaction_parse(card_data, sector, block, byte)
        transactions.append(t)

    # Trova la transazione con la data più recente
    max_idx = max(range(len(transactions)), key=lambda i: transactions[i]["date"])

    # Rotazione: sposta gli elementi in modo che la più recente sia all'inizio
    # (questo replica la logica di "rotazione" della versione C)
    transactions = transactions[max_idx+1:] + transactions[:max_idx+1]
    transactions.reverse()  # ora la transazione più recente è la prima

    return transactions

# Parsing dei pass (settori 4 e 5)
def pass_parse(card_data: bytes, sector: int, block: int, byte: int):
    val = pos_to_num(card_data, sector, block, byte, 6)
    # Se il campo è "vuoto", viene usato il valore 0x002000000000
    if val == 0x002000000000:
        return {"valid": False}
    pre = pos_to_num(card_data, sector, block, byte, 2) >> 6
    post = (pos_to_num(card_data, sector, block, byte+4, 2) >> 2) & 0x3FF
    p_date = end_validity_parse(card_data, sector, block, byte+1)
    return {
        "valid": True,
        "pre": pre,
        "post": post,
        "date": p_date
    }

def passes_parse(card_data: bytes):
    passes = []
    for i in range(CHARLIE_N_PASSES):
        sector = 4 + (i // 2)
        block = 0
        byte = (i % 2) * 7
        p = pass_parse(card_data, sector, block, byte)
        passes.append(p)
    return passes

# Funzioni di formattazione

def format_money(money_tuple):
    dollars, cents = money_tuple
    return f"${dollars}.{cents:02d}"

def format_datetime(dt: datetime) -> str:
    return dt.strftime("%d/%m/%Y %H:%M:%S")

def format_transaction(tx):
    sign = "-" if (tx["g_flag"] & 0x1) else "+"
    base = f"{format_datetime(tx['date'])}\n{sign}{format_money(tx['fare'])}"
    # Se l'importo corrisponde a quello di bus (ad es. $1.70) si aggiunge il numero di "gate"
    if (tx["g_flag"] & 0x1) and (tx["fare"] == (1, 70)):
        base += f"   #{tx['gate']}"
    elif tx["gate"] in fare_gate_ids:
        base += f"   #{tx['gate']} ({fare_gate_ids[tx['gate']]})"
    else:
        base += f"   #{tx['gate']}"
    # In modalità debug si potrebbero mostrare anche i flag
    return base

def format_pass(p):
    if not p.get("valid", False):
        return ""
    return f"\n-Pre: {p['pre']}\n-Post: {charliecard_types.get(p['post'], 'Unknown-'+str(p['post']))}\n-Date: {format_datetime(p['date'])}\n"

# Funzione principale che esegue il parsing e restituisce una stringa con i dati estratti
def parse_charliecard(card_data: bytes, debug: bool=False) -> str:
    output = []
    # Identificazione della carta: prendiamo il numero serial (UID)
    card_number = mfg_sector_parse(card_data)
    output.append("CharlieCard")
    output.append(f"Serial: 5-{card_number}")
    
    # Legge il settore dei contatori per determinare il settore attivo e il numero di usi
    n_uses, active_sector = counter_sector_parse(card_data)
    
    # Legge il settore del bilancio
    balance_sector = balance_sector_parse(card_data, active_sector)
    output.append(f"Bal: {format_money(balance_sector['balance'])}")
    # Formatta il tipo di carta tramite il mapping
    card_type_str = charliecard_types.get(balance_sector["type"], f"Unknown-{balance_sector['type']}")
    output.append(f"Type: {card_type_str}")
    output.append(f"Trip Count: {n_uses}")
    output.append(f"Issued: {format_datetime(balance_sector['issued'])}")
    # Visualizza la data di scadenza se significativa
    if balance_sector["end_validity"] != CHARLIE_EPOCH and balance_sector["end_validity"] > balance_sector["issued"]:
        output.append(f"Expiry: {format_datetime(balance_sector['end_validity'])}")
    
    # Transazioni
    transactions = transactions_parse(card_data)
    output.append("Transactions:")
    for tx in transactions:
        output.append(format_transaction(tx))
    
    # Pass (solo in debug, se presenti)
    if debug:
        passes = passes_parse(card_data)
        valid_passes = [p for p in passes if p.get("valid", False)]
        if valid_passes:
            output.append("\nPasses (DEBUG / WIP):")
            for i, p in enumerate(valid_passes, start=1):
                output.append(f"\nPass {i}")
                output.append(format_pass(p))
    
    return "\n".join(output)

# Esempio di utilizzo:
if __name__ == '__main__':
    # Supponiamo di avere un file binario con il dump della carta (es. "charliecard_dump.bin")
    try:
        with open("charliecard_dump.bin", "rb") as f:
            card_data = f.read()
        result = parse_charliecard(card_data, debug=True)
        print(result)
    except FileNotFoundError:
        print("File dump della carta non trovato. Assicurati di aver fornito un file valido.")

