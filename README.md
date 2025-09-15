# Flipper HIDecoder
<img width="55%" height="55%" alt="image" src="https://github.com/user-attachments/assets/78f8f39d-6414-4a85-81e0-e9372be7030a" />

This Python code enables the quick decoding and conversion of 26-bit HID card data from the traditional ESP RFID Tool's HEX format to a usable Flipper HEX format for the Flipper Zero's HID H10301 card data while displaying the FC (Facility Code) and CN (Card Number). This script was presented at the BSides Caymans 2025 conference as part of the Flipside: Remote Badge Cloning Workshop.

 *Disclaimer:* **This guide is for educational and ethical hacking purposes ONLY. All penetration testing activities must be authorized by all relevant parties.**

If you have ever worked with the ESP RFID tool, you will notice a string of HEX code after the binary data. The HEX from the ESP RFID Tool is used for the Proxmark3. For a few years now, the Flipper Zero has made it easier for Red Teamers to duplicate card data in the field. If you're on a badge cloning mission for a client, the ESP RFID tool is still a strong choice for [remote badge cloning](https://github.com/sh0ckSec/RFID-Gooseneck) options. The manual process to convert the 26-bit binary data into a Flipper Zero Hex looks like this:

<img width="70%" height="70%" alt="image" src="https://github.com/user-attachments/assets/dea63c6d-937e-405b-a7d8-cfcd876433f1" />
<img width="70%" height="70%" alt="image" src="https://github.com/user-attachments/assets/ff589ba5-915e-4fb2-bf62-64e564129af0" />

## FlipperHIDecoder.py
 With this Python code, you can enter the raw HEX and decode and convert your payload quickly and easily.

<img width="70%" height="70%" alt="image" src="https://github.com/user-attachments/assets/84b529ac-bf4a-427c-902d-a0f60e26debb" />


 Enter the Flipper HEX data into your H10301 option and boom! You now have the correct card data to continue your mission. Example:

<img width="70%" height="70%" alt="image" src="https://github.com/user-attachments/assets/25e152a0-675e-4be2-88c3-86c83642e471" />
<img width="70%" height="70%" alt="image" src="https://github.com/user-attachments/assets/d2876370-91b2-4533-8709-c20f4b24f49d" />
<img width="70%" height="70%" alt="image" src="https://github.com/user-attachments/assets/3462a0a3-a00c-4159-9935-01cfb505b5e6" />
<img width="70%" height="70%" alt="image" src="https://github.com/user-attachments/assets/9ae37371-a82a-40bd-a100-94340b4efb9d" />


## HID Card Bit Breakdown

In a Wiegand-format card (HID 26, 34, 37, etc.), the first bit and the last bit are parity bits — they’re not part of the Facility Code or Card Number.

* Bit 1 (leading bit): Even parity check
* Last bit (trailing bit): Odd parity check

These two parity bits are used by the reader to validate that the data was transmitted correctly.

### Even Parity Rule (Leading Bit)

* This covers the first half of the data bits (excluding the parity itself).

Example for 26-bit Wiegand:

* Bits 2 → 13 are checked.
* The parity bit (bit 1) is set so that the total number of 1s in bits 1–13 is even.

So if bits 2–13 already contain an even number of `1s`, the leading parity bit will be `01`. If they contain an odd number, the leading parity will be 1 (to force the total count even).

### Odd Parity Rule (Trailing Bit)
* This covers the second half of the data bits (excluding itself).

Example for 26-bit Wiegand:

* Bits 14 → 25 are checked.

* The trailing parity bit (bit 26) is set so that the total number of `1s` in bits 14–26 is odd.

So if bits 14–25 already have an odd number of 1s, the trailing parity will be `0`.
If they have an even number, the trailing parity will be `1` (forcing the total odd).

Labeling the 26-bit payload as W1..W26:
```
W#    1  2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26
bits  0  0 0 0 1 0 0 0 1  0  0  0  0  0  1  0  1  0  0  1  1  1  0  0  1  1
```
Group into the standard Wiegand-26 fields:

* W1 — Even parity over W2..W13 = `0`
* W2..W9 — Facility Code (8 bits) = 00100001 (binary) → `33` (decimal)
* W10..W25 — Card number (16 bits) = 0000010100111001 (binary) → `1337` (decimal)
* W26 — Odd parity over W14..W25 = `1`
```
W1 | W2..W9         | W10................W25         | W26
 0 | 00100001 (FC=33)| 0000010100111001 (CN=1337)   | 1
```
Future updates will include other formats besides 26-bit after testing is complete. Thanks! 
<img width="40%" height="40%" alt="BsidesCaymansLogo" src="https://github.com/user-attachments/assets/98ce5282-2e61-4891-9082-9106289bce15" />

