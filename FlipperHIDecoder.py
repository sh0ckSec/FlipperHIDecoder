#!/usr/bin/env python3

# ANSI color codes
GREEN  = "\033[92m"
RED    = "\033[91m"
ORANGE = "\033[38;5;208m"  # 256-color orange
RESET  = "\033[0m"

def hex_to_bits(hex_str):
    """Convert hex string to binary string (no 0x prefix)."""
    return ''.join(f"{int(c, 16):04b}" for c in hex_str)

def decode_hid(raw_hex):
    bits = hex_to_bits(raw_hex)
    formats = [(26, 14), (33, 14), (34, 14), (35, 14), (37, 14)]
    results = []

    for wiegand_bits, header_len in formats:
        required_len = header_len + wiegand_bits
        if len(bits) < required_len:
            continue

        header_bits = bits[:header_len]
        payload_bits = bits[header_len:header_len + wiegand_bits]
        W1 = int(payload_bits[0], 2)
        W_last = int(payload_bits[-1], 2)

        if wiegand_bits == 26:
            fc_bits = payload_bits[1:9]
            cn_bits = payload_bits[9:25]
            even_range = payload_bits[1:13]
            odd_range = payload_bits[13:25]
        elif wiegand_bits == 33:
            fc_bits = payload_bits[1:9]
            cn_bits = payload_bits[9:32]
            even_range = payload_bits[1:17]
            odd_range = payload_bits[17:32]
        elif wiegand_bits == 34:
            fc_bits = payload_bits[1:17]
            cn_bits = payload_bits[17:33]
            even_range = payload_bits[1:17]
            odd_range = payload_bits[17:33]
        elif wiegand_bits == 35:
            fc_bits = payload_bits[1:13]
            cn_bits = payload_bits[13:34]
            even_range = payload_bits[1:18]
            odd_range = payload_bits[18:34]
        elif wiegand_bits == 37:
            fc_bits = payload_bits[1:15]
            cn_bits = payload_bits[15:35]
            even_range = payload_bits[1:18]
            odd_range = payload_bits[18:35]
        else:
            continue

        FC = int(fc_bits, 2)
        CN = int(cn_bits, 2)
        even_count = sum(int(b) for b in even_range)
        odd_count = sum(int(b) for b in odd_range)

        even_ok = (even_count % 2 == 0 and W1 == 0) or (even_count % 2 == 1 and W1 == 1)
        odd_ok = (odd_count % 2 == 1 and W_last == 0) or (odd_count % 2 == 0 and W_last == 1)

        score = even_ok + odd_ok
        results.append((score, wiegand_bits, header_bits, payload_bits, FC, CN, even_ok, odd_ok))

    if not results:
        print("No valid HID format detected.")
        return

    best = sorted(results, key=lambda x: x[0], reverse=True)[0]
    _, wb, header_bits, payload_bits, FC, CN, even_ok, odd_ok = best

    print(f"\nHID Prox TAG ID  : {raw_hex} ({len(bits)} bits)")
    print(f"DETECTED FORMAT  : HID {wb}-bit")
#    print(f"HEADER           : {header_bits}")
    print(f"WIEGAND {wb}       : {payload_bits}")
    print(f"Facility Code    : {FC}")
    print(f"Card Number      : {CN}")
    print(f"Even Parity      : {GREEN}PASS{RESET}" if even_ok else f"Even parity      : {RED}FAIL{RESET}")
    print(f"Odd Parity       : {GREEN}PASS{RESET}" if odd_ok else f"Odd parity       : {RED}FAIL{RESET}")

    # --- Flipper H10301 conversion ---
    if wb == 26:
        # payload_bits is 26 bits: [parity][FC:8][CN:16][parity]
        middle24 = payload_bits[1:-1]             # remove leading & trailing parity bits
        flipper_hex = f"{int(middle24, 2):06X}"   # 24 bits -> 6 hex digits
        flipper_bytes = " ".join(f"{int(middle24[i:i+8], 2):02X}" for i in range(0, 24, 8))
        print(f"Flipper HID 10301 HEX: {ORANGE}{flipper_bytes}{RESET}")

if __name__ == "__main__":
    raw_hex = input("Enter raw HEX from ESP-RFID Tool: ").strip().upper()
    decode_hid(raw_hex)
