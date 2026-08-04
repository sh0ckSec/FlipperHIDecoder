<img width="1822" height="174" alt="image" src="https://github.com/user-attachments/assets/3ab48d82-3fc3-4300-9ce7-ae220eb13c8a" />

<p align="center">
<img width="30%" height="30%" alt="image" src="https://github.com/user-attachments/assets/447ddd59-dfeb-4ac7-aab6-d56e3f39223a" />
</p>

This python code allows you to quickly decode and convert 26-bit HID card data from the traditional ESP RFID Tool's HEX into a useable Flipper HEX format for the Flipper Zero's HID H10301 card data format. This script was presented at the BSides Caymans 2025 conference as part of the Flipside: Remote Badge Cloning Workshop and has undergone a massive overhaul for DEF CON 34's talk **Clone to Pwn - Remote Badge Cloning with the Flipper Zero** Note: This script currently works best with HID 26-Bit cards. 

 *Disclaimer:* **This guide is for educational and ethical hacking purposes ONLY. All penetration testing activities must be authorized by all relevant parties.**

<img width="2306" height="1140" alt="image" src="https://github.com/user-attachments/assets/03cefc24-7a4e-4c08-aae9-1c1b5435b5e2" />

### FlipperHIDecoder.py

```
usage: FlipperHIDecoder.py [-h] [--version] [--pm3 HEX | --loot FILE]
                           [--detail] [--verbose] [--stats] [--only-valid]
                           [--csv] [--json] [--markdown] [--output FILE]
                           [--export ZIP] [--export-all DIR] [--overwrite]
                           [--no-fallback] [--no-banner]

Flipper HIDecoder v3.2.5

Decode authorized ESP-RFID Tool / Proxmark3 HEX captures into
facility codes, card numbers, parity results, and Flipper-style HEX.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --pm3, -pm3, --raw HEX
                        decode one Proxmark3/ESP-RFID hexadecimal capture
  --loot, -l, --log FILE
                        parse an ESP-RFID loot/log file from line 3
  --detail              add parity, Wiegand bits, window, source, and
                        confidence
  --verbose             show capture and candidate-selection details
  --stats               print a summary after the results
  --only-valid          hide captures that could not be decoded
  --csv                 write CSV to stdout
  --json                write JSON
  --markdown            write a Markdown table
  --output, -o, --out FILE
                        write the selected text format to a file
  --export ZIP          export valid-card CSV/JSON inventory manifests to a
                        ZIP archive
  --export-all DIR      export redacted H10301 .rfid templates and inventory
                        manifests
  --overwrite           replace an existing output file
  --no-fallback         do not try other lengths when the reported length is
                        unusable
  --no-banner           suppress the startup banner

Examples:
  FlipperHIDecoder.py --pm3 2004420A73
  FlipperHIDecoder.py --loot loot.txt
  FlipperHIDecoder.py --loot loot.txt --detail --stats
  FlipperHIDecoder.py --loot loot.txt --csv > cards.csv
  FlipperHIDecoder.py --loot loot.txt --json --output cards.json
  FlipperHIDecoder.py --loot loot.txt --export cards_inventory.zip
  FlipperHIDecoder.py --pm3 2004420A73 --verbose

Input:
  --pm3 HEX              Decode one Proxmark3/ESP-RFID HEX capture
  --loot FILE            Parse an ESP-RFID loot/log file from line 3

Display:
  --detail               Add parity, Wiegand bits, window, source, confidence
  --verbose              Show capture and candidate-selection details
  --stats                Print the processing summary
  --only-valid           Hide undecodable captures
  --no-banner            Suppress the startup banner

Output:
  --csv                  Output CSV
  --json                 Output JSON
  --markdown             Output a Markdown table
  --output FILE          Write the selected output format to a file
  --export ZIP           Export valid-card CSV/JSON inventory manifests to ZIP
  --export-all DIR       Export redacted H10301 templates and manifests
  --zip-manifest FILE    Alias for --export
  --overwrite            Replace existing output files

Decoder:
  --no-fallback          Do not try other lengths when the reported length fails

Configured formats:
  26-bit  HID H10301       8-bit FC / 16-bit CN
  33-bit  Generic/D10202   7-bit FC / 24-bit CN
  34-bit  HID H10306      16-bit FC / 16-bit CN
  35-bit  Corporate 1000  12-bit FC / 20-bit CN
  37-bit  HID H10304      16-bit FC / 19-bit CN
```

## Single Payload Input
 With this Python code, you can enter the raw HEX and decode and convert your payload quickly and easily.
 
```python3 FlipperHIDecoder.py -pm3 2004440A73``` 

<img width="1132" height="761" alt="defconSingle" src="https://github.com/user-attachments/assets/98518657-6319-4814-9627-0bcc3880e0b3" style="width: 80%; height: auto;" />

## Multiple Payloads
You can easily parse the entire ESP-RFID log.txt file all at once. 

```python3 FlipperHIDecoder.py -l log.txt``` 

<img width="1132" height="761" alt="defconBatch" src="https://github.com/user-attachments/assets/9a2ec737-81b8-4209-88b1-4312523b8ec8" style="width: 80%; height: auto;" />


### Background
If you have ever worked with the ESP RFID tool, you will notice a string of HEX code after the binary data. The HEX from the ESP RFID Tool is used for the Proxmark3. For a few years now, the Flipper Zero has made it easier for Red Teamers to duplicate card data in the field. If you're on a badge cloning mission for a client, the ESP RFID tool is still a strong choice for [remote badge cloning](https://github.com/sh0ckSec/RFID-Gooseneck) options. The manual process to convert the 26-bit binary data into a Flipper Zero Hex looks like this:

<img width="2166" height="932" alt="image" src="https://github.com/user-attachments/assets/fe8ffebc-ec72-4e50-88dd-7ade7e253b98" />
Once you remove the leading and trailing parity bits you'll be left with your full badge payload.

<img width="1936" height="1068" alt="image" src="https://github.com/user-attachments/assets/f43f1095-7c5c-468b-806c-bacdf2d69d4e" />



 Enter the Flipper HEX data into your H10301 option and boom! You now have the correct card data to continue your mission.

 ### Steps: 
 
 ```Select 125khz > Add Manually > HID10301 > Enter 22 05 39 > Save > Name the Card > Save```



<img width="400" height="245" alt="1-Defcon34Card-Manual-Recording 2026-07-31 120754" src="https://github.com/user-attachments/assets/7eac262f-4dc8-428d-8913-eee51ca9dedc" />

Now you can easily write your payload to a physical RFID Card.

<img width="50%" height="50%" alt="2-WritingCard-Recording 2026-07-31 121855" src="https://github.com/user-attachments/assets/6e5a2f2d-29b8-436c-a7d6-a02f08056f8c" />



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
### Future Features
* Additional bit rate support.
* Exporting loot to .rfid files for seamless drag and drop onto your Flipper's SD card.
* Supporting conversion for other vendors. 
<img width="242" height="203" alt="DC34_icon" src="https://github.com/user-attachments/assets/92f42562-e62a-47f4-8821-887934bcfbda" />
<img width="40%" height="40%" alt="BsidesCaymansLogo" src="https://github.com/user-attachments/assets/98ce5282-2e61-4891-9082-9106289bce15" />

This script was Co-Authored with ChatGPT.
