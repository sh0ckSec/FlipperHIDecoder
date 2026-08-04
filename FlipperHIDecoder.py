#!/usr/bin/env python3

"""
Flipper HIDecoder v3.2.5

Parse ESP-RFID logs or a single raw hexadecimal capture, locate supported
Wiegand frames, decode facility/card fields, inspect parity, and export an
inventory as terminal table, CSV, JSON, Markdown, or a ZIP manifest.

This utility intentionally does not generate credential-emulation files.
Use it only with systems and credentials you are authorized to assess.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import shutil
import time
import re
import sys
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

VERSION = "3.2.5"

# ANSI colors
GRAY = "[90m"
CYAN = "[96m"
YELLOW = "[93m"
ORANGE = "[38;5;208m"
PURPLE = "[95m"
RED = "[91m"
GREEN = "[92m"
WHITE_BOLD = "[1;97m"
RESET = "[0m"


DOLPHIN_BANNER = r"""▀█▀▀█ ▀█   ▀                               █   █ ▀█▀ ▀█▀▀▄                     ▀█
 █▄▄   █  ▀█  ▀█▀▀▄ ▀█▀▀▄ ▄▀▀▀▄ ▀█▄▀▄      █▄▄▄█  █   █  █ ▄▀▀▀▄ ▄▀▀▀▄ ▄▀▀▀▄  ▄▄█  ▄▀▀▀▄ ▀█▄▀▄
 █     █   █   █▄▄▀  █▄▄▀ █▀▀▀▀  █  ▀      █   █  █   █  █ █▀▀▀▀ █   ▄ █   █ █  █  █▀▀▀▀  █  ▀
▀▀▀   ▀▀▀ ▀▀▀  █     █     ▀▀▀  ▀▀▀        ▀   ▀ ▀▀▀ ▀▀▀▀   ▀▀▀   ▀▀▀   ▀▀▀   ▀▀ ▀  ▀▀▀  ▀▀▀"""


def supports_color(stream: io.TextIOBase = sys.stdout) -> bool:
    if os.environ.get("NO_COLOR") is not None or not getattr(stream, "isatty", lambda: False)():
        return False
    if os.name == "nt":
        try:
            os.system("")
        except OSError:
            return False
    return True


def colorize(text: str, color: str, stream: io.TextIOBase = sys.stdout) -> str:
    return f"{color}{text}{RESET}" if supports_color(stream) else text


def center_text(text: str, width: int) -> str:
    return text.center(max(width, len(text)))


def terminal_width(minimum: int = 48, maximum: int = 120) -> int:
    return min(max(shutil.get_terminal_size((100, 24)).columns, minimum), maximum)


def print_banner(no_color: bool = False) -> None:
    divider = "═" * terminal_width()

    # Add space between the command line and the banner.
    print()

    if no_color or not supports_color():
        print(DOLPHIN_BANNER)
        print(f"Flipper HIDecoder v{VERSION}")
        print("Converting ESP-RFID Tool Proxmark3 Hex to Flipper Zero HEX and more.")
        print("Author: @sh0ckSec")
        print()
        print(divider)
        return

    print(colorize(DOLPHIN_BANNER, ORANGE))
    print()
    print(
        f"{colorize('Flipper', ORANGE)} "
        f"{colorize('HIDecoder', WHITE_BOLD)} "
        f"{colorize(f'v{VERSION}', CYAN)}"
    )
    print(colorize(
        "Converting ESP-RFID Tool Proxmark3 Hex to Flipper Zero HEX and more.",
        GRAY,
    ))
    print(colorize("Author: @sh0ckSec", PURPLE))
    print()

def status(message: str, kind: str = "info") -> None:
    symbols = {"ok": "[+]", "warn": "[!]", "error": "[-]", "info": "[*]"}
    colors = {"ok": GREEN, "warn": YELLOW, "error": RED, "info": CYAN}
    prefix = symbols.get(kind, "[*]")
    print(f"{colorize(prefix, colors.get(kind, CYAN))} {message}")


# ---------------------------------------------------------------------------
# Data model and format registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FormatDefinition:
    bit_length: int
    name: str
    fc_slice: tuple[int, int]
    cn_slice: tuple[int, int]
    even_slice: tuple[int, int]
    odd_slice: tuple[int, int]
    max_fc: int
    max_cn: int
    known_format: bool = True


# Known/common layouts used by this decoder.
#
# A reported bit length alone does not always identify a unique Wiegand
# format. In particular, 33-bit is displayed as generic and uses the
# D10202-style 7-bit FC / 24-bit CN layout as a configured interpretation.
FORMATS: dict[int, FormatDefinition] = {
    26: FormatDefinition(
        26, "HID H10301", (1, 9), (9, 25), (1, 13), (13, 25),
        max_fc=0xFF, max_cn=0xFFFF,
    ),
    33: FormatDefinition(
        33, "Generic 33-bit", (1, 8), (8, 32), (1, 17), (16, 32),
        max_fc=0x7F, max_cn=0xFFFFFF, known_format=False,
    ),
    34: FormatDefinition(
        34, "HID H10306", (1, 17), (17, 33), (1, 17), (17, 33),
        max_fc=0xFFFF, max_cn=0xFFFF,
    ),
    35: FormatDefinition(
        35, "HID Corporate 1000", (2, 14), (14, 34), (0, 0), (0, 0),
        max_fc=0xFFF, max_cn=0xFFFFF,
    ),
    37: FormatDefinition(
        37, "HID H10304", (1, 17), (17, 36), (1, 19), (18, 36),
        max_fc=0xFFFF, max_cn=0x7FFFF,
    ),
}


@dataclass
class Capture:
    loot: int
    raw_hex: str = ""
    binary: str = ""
    reported_bits: int | None = None
    source_line: int | None = None
    source_text: str = ""
    unknown: bool = False


@dataclass
class Candidate:
    format_bits: int
    card_type: str
    payload_bits: str
    facility_code: int
    card_number: int
    even_ok: bool
    odd_ok: bool
    window_start: int
    window_end: int
    source: str
    score: int
    fc_in_range: bool
    cn_in_range: bool
    known_format: bool

    @property
    def parity_ok(self) -> bool:
        return self.even_ok and self.odd_ok

    @property
    def payload_hex(self) -> str:
        width = (len(self.payload_bits) + 3) // 4
        return f"{int(self.payload_bits, 2):0{width}X}"

    @property
    def data_hex(self) -> str:
        """Return Flipper HID 10301 data bytes for 26-bit cards only.

        Flipper HID 10301 uses the 24 data bits between the two Wiegand
        parity bits: 8-bit facility code + 16-bit card number. Longer
        Wiegand formats must not be rendered as HID 10301 data.
        """
        if self.format_bits != 26 or len(self.payload_bits) != 26:
            return ""
        data = self.payload_bits[1:-1]
        return " ".join(
            f"{int(data[i:i + 8], 2):02X}" for i in range(0, 24, 8)
        )


@dataclass
class DecodedCard:
    loot: int
    valid: bool
    raw_hex: str
    bit_length: int | None = None
    card_type: str = "N/A"
    facility_code: int | None = None
    card_number: int | None = None
    payload_data: str = ""
    payload_bits: str = ""
    parity_ok: bool | None = None
    window: str = ""
    source: str = ""
    confidence: int = 0
    reason: str = ""
    source_line: int | None = None


# ---------------------------------------------------------------------------
# Input normalization and parsing
# ---------------------------------------------------------------------------

HEX_RE = re.compile(r"^[0-9A-F]+$")


def normalize_hex(value: str) -> str:
    """Normalize 0x-prefixed, spaced, dashed, or odd-length hexadecimal."""
    cleaned = re.sub(r"[\s:_-]+", "", value.strip()).upper()
    if cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    if not cleaned or not HEX_RE.fullmatch(cleaned):
        raise ValueError("value is not valid hexadecimal")
    return cleaned


def normalize_binary(value: str) -> str:
    cleaned = re.sub(r"[^01]", "", value or "")
    return cleaned


def hex_to_bits(value: str) -> str:
    """Convert each entered hex digit to four bits; odd digit counts are valid."""
    normalized = normalize_hex(value)
    return "".join(f"{int(ch, 16):04b}" for ch in normalized)


def parse_log_line(line: str, loot: int, line_number: int) -> Capture:
    stripped = line.strip()
    first_section = stripped.split(",", 1)[0].strip() if stripped else ""
    unknown = first_section.casefold().startswith("unknown")

    bits_match = re.search(r"(\d+)\s*bit", first_section, re.IGNORECASE)
    hex_match = re.search(r"\bHEX\s*:\s*([0-9A-Fa-f\s:_-]+)\s*$", stripped)
    binary_match = re.search(
        r"\bBinary\s*:\s*([01\s]+?)(?=\s*,\s*[A-Za-z]+\s*:|$)",
        stripped,
        re.IGNORECASE,
    )

    raw_hex = ""
    if hex_match:
        try:
            raw_hex = normalize_hex(hex_match.group(1))
        except ValueError:
            raw_hex = re.sub(r"\s+", "", hex_match.group(1)).upper()

    return Capture(
        loot=loot,
        raw_hex=raw_hex,
        binary=normalize_binary(binary_match.group(1)) if binary_match else "",
        reported_bits=int(bits_match.group(1)) if bits_match else None,
        source_line=line_number,
        source_text=stripped,
        unknown=unknown,
    )


def load_log(path: Path, start_line: int = 3) -> list[Capture]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise RuntimeError(f"Unable to read log file '{path}': {exc}") from exc

    captures: list[Capture] = []
    loot = 1
    for line_number, line in enumerate(lines, start=1):
        if line_number < start_line or not line.strip():
            continue
        captures.append(parse_log_line(line, loot, line_number))
        loot += 1
    return captures


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------


def slice_value(payload: str, bounds: tuple[int, int]) -> int:
    start, end = bounds
    return int(payload[start:end], 2)


def parity_status(payload: str, fmt: FormatDefinition) -> tuple[bool, bool]:
    # HID Corporate 1000 35-bit uses three interleaved parity bits rather
    # than the simple leading-even / trailing-odd scheme used by H10301.
    if fmt.bit_length == 35:
        packed = int(payload, 2)
        bot = packed & 0xFFFFFFFF
        mid = (packed >> 32) & 0x7

        expected_mid1 = ((mid & 0x1) ^ (bot & 0xB6DB6DB6)).bit_count() & 1
        expected_bot0 = 1 ^ (((mid & 0x3) ^ (bot & 0x6DB6DB6C)).bit_count() & 1)
        expected_mid2 = 1 ^ (((mid & 0x3) ^ bot).bit_count() & 1)

        check_a = expected_mid1 == ((mid >> 1) & 1)
        check_b = expected_bot0 == (bot & 1)
        check_c = expected_mid2 == ((mid >> 2) & 1)
        return check_a and check_b, check_c

    leading = int(payload[0])
    trailing = int(payload[-1])
    even_data = payload[slice(*fmt.even_slice)]
    odd_data = payload[slice(*fmt.odd_slice)]

    even_ok = (leading + even_data.count("1")) % 2 == 0
    odd_ok = (trailing + odd_data.count("1")) % 2 == 1
    return even_ok, odd_ok


def decode_window(
    stream: str,
    fmt: FormatDefinition,
    start: int,
    source: str,
    reported_bits: int | None,
) -> Candidate:
    payload = stream[start:start + fmt.bit_length]
    even_ok, odd_ok = parity_status(payload, fmt)

    facility_code = slice_value(payload, fmt.fc_slice)
    card_number = slice_value(payload, fmt.cn_slice)
    fc_in_range = 0 <= facility_code <= fmt.max_fc
    cn_in_range = 0 <= card_number <= fmt.max_cn

    # Weighted confidence model:
    #   parity fully passes                 +50
    #   one parity region passes            +25
    #   facility code is in-format          +15
    #   card number is in-format            +15
    #   matches ESP-RFID reported length    +15
    #   recognized named format              +5
    #
    # Binary input and right-edge alignment are small tie-breakers.
    parity_score = 50 if (even_ok and odd_ok) else 25 if (even_ok or odd_ok) else 0
    range_score = 15 * int(fc_in_range) + 15 * int(cn_in_range)
    hint_score = 15 if reported_bits == fmt.bit_length else 0
    format_score = 5 if fmt.known_format else 0
    source_score = 3 if source == "Binary" else 0
    distance_from_end = len(stream) - (start + fmt.bit_length)
    alignment_score = max(0, 2 - distance_from_end)
    score = (
        parity_score
        + range_score
        + hint_score
        + format_score
        + source_score
        + alignment_score
    )

    return Candidate(
        format_bits=fmt.bit_length,
        card_type=fmt.name,
        payload_bits=payload,
        facility_code=facility_code,
        card_number=card_number,
        even_ok=even_ok,
        odd_ok=odd_ok,
        window_start=start + 1,
        window_end=start + fmt.bit_length,
        source=source,
        score=score,
        fc_in_range=fc_in_range,
        cn_in_range=cn_in_range,
        known_format=fmt.known_format,
    )


def candidates_for_stream(
    stream: str,
    source: str,
    formats: Sequence[FormatDefinition],
    reported_bits: int | None,
) -> list[Candidate]:
    candidates: list[Candidate] = []
    for fmt in formats:
        if len(stream) < fmt.bit_length:
            continue
        for start in range(0, len(stream) - fmt.bit_length + 1):
            candidates.append(decode_window(stream, fmt, start, source, reported_bits))
    return candidates


def candidate_sort_key(candidate: Candidate) -> tuple[int, int, int, int, int, int, int]:
    return (
        candidate.score,
        int(candidate.parity_ok),
        int(candidate.fc_in_range and candidate.cn_in_range),
        int(candidate.known_format),
        -candidate.format_bits,
        candidate.window_end,
        -candidate.window_start,
    )


def decode_capture(capture: Capture, fallback_formats: bool = True) -> tuple[DecodedCard, list[Candidate]]:
    if capture.unknown:
        return (
            DecodedCard(
                loot=capture.loot,
                valid=False,
                raw_hex=capture.raw_hex,
                reason="Log line begins with Unknown",
                source_line=capture.source_line,
            ),
            [],
        )

    streams: list[tuple[str, str]] = []
    if capture.binary:
        streams.append((capture.binary, "Binary"))
    if capture.raw_hex:
        try:
            streams.append((hex_to_bits(capture.raw_hex), "HEX"))
        except ValueError:
            pass

    if not streams:
        return (
            DecodedCard(
                loot=capture.loot,
                valid=False,
                raw_hex=capture.raw_hex,
                reason="No usable Binary or HEX field",
                source_line=capture.source_line,
            ),
            [],
        )

    hinted = FORMATS.get(capture.reported_bits or -1)
    primary_formats = [hinted] if hinted else list(FORMATS.values())
    primary_formats = [fmt for fmt in primary_formats if fmt is not None]

    candidates: list[Candidate] = []
    for stream, source in streams:
        candidates.extend(candidates_for_stream(stream, source, primary_formats, capture.reported_bits))

    # The ESP-RFID bit field is a strong hint. Search other formats only when
    # the hinted format cannot be extracted at all.
    if not candidates and fallback_formats:
        fallback = [fmt for fmt in FORMATS.values() if fmt.bit_length != capture.reported_bits]
        for stream, source in streams:
            candidates.extend(candidates_for_stream(stream, source, fallback, capture.reported_bits))

    if not candidates:
        return (
            DecodedCard(
                loot=capture.loot,
                valid=False,
                raw_hex=capture.raw_hex,
                reason="Capture is shorter than the requested/supported frame",
                source_line=capture.source_line,
            ),
            [],
        )

    winner = max(candidates, key=candidate_sort_key)
    confidence = min(100, max(0, winner.score))
    return (
        DecodedCard(
            loot=capture.loot,
            valid=True,
            raw_hex=capture.raw_hex,
            bit_length=winner.format_bits,
            card_type=winner.card_type,
            facility_code=winner.facility_code,
            card_number=winner.card_number,
            payload_data=winner.data_hex,
            payload_bits=winner.payload_bits,
            parity_ok=winner.parity_ok,
            window=f"{winner.window_start}-{winner.window_end}",
            source=winner.source,
            confidence=confidence,
            reason="",
            source_line=capture.source_line,
        ),
        sorted(candidates, key=candidate_sort_key, reverse=True),
    )


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------


def card_to_record(card: DecodedCard, detail: bool) -> dict[str, str | int]:
    if card.valid:
        record: dict[str, str | int] = {
            "Loot": card.loot,
            "Bit": card.bit_length or "",
            "Card Type": card.card_type,
            "PM3 Hex": card.raw_hex,
            "FC": card.facility_code if card.facility_code is not None else "",
            "CN": card.card_number if card.card_number is not None else "",
            "Flipper Hex": card.payload_data or "N/A",
        }
        if detail:
            record.update(
                {
                    "Notes": "Parity PASS" if card.parity_ok else "Parity FAIL",
                    "Wiegand Bits": card.payload_bits,
                    "Window": card.window,
                    "Source": card.source,
                    "Confidence": f"{card.confidence}%",
                }
            )
        return record

    record = {
        "Loot": card.loot,
        "Bit": "Invalid",
        "Card Type": "N/A",
        "PM3 Hex": card.raw_hex,
        "FC": "N/A",
        "CN": "N/A",
        "Flipper Hex": "",
    }
    if detail:
        record.update(
            {
                "Notes": card.reason or "Invalid",
                "Wiegand Bits": "",
                "Window": "",
                "Source": "",
                "Confidence": "0%",
            }
        )
    return record


def filter_cards(cards: Iterable[DecodedCard], only_valid: bool) -> list[DecodedCard]:
    return [card for card in cards if card.valid or not only_valid]


def color_for_column(column: str, value: str) -> str | None:
    if column == "Card Type":
        return GRAY
    if column == "FC":
        return CYAN
    if column == "CN":
        return YELLOW
    if column == "Flipper Hex":
        return ORANGE
    if column == "Bit" and value == "Invalid":
        return RED
    if column == "Notes":
        if value == "Parity PASS":
            return GREEN
        if value == "Parity FAIL" or value not in {"", "N/A"}:
            return RED
    return None


def render_table(cards: Sequence[DecodedCard], detail: bool, only_valid: bool) -> str:
    selected = filter_cards(cards, only_valid)
    records = [card_to_record(card, detail) for card in selected]

    if not records:
        return "No rows to display."

    columns = list(records[0].keys())
    numeric_columns = {"Loot", "Bit", "FC", "CN", "Confidence"}

    # Dynamic sizing naturally handles FC and CN based on the largest values.
    widths = {
        column: max(
            len(column),
            *(len(str(record.get(column, ""))) for record in records),
        )
        for column in columns
    }

    # Reasonable display caps for text-heavy columns.
    caps = {
        "Card Type": 24,
        "PM3 Hex": 18,
        "Flipper Hex": 18,
        "Notes": 14,
        "Wiegand Bits": 40,
        "Window": 12,
        "Source": 10,
        "Confidence": 10,
    }
    for column, maximum in caps.items():
        if column in widths:
            widths[column] = min(widths[column], maximum)

    def total_width() -> int:
        return sum(widths[column] for column in columns) + 3 * (len(columns) - 1)

    # Adapt the table to the current terminal width by shrinking long text
    # columns first. Numeric values remain untruncated whenever possible.
    available = terminal_width(48, 160)
    shrink_order = [
        "Wiegand Bits",
        "Card Type",
        "PM3 Hex",
        "Flipper Hex",
        "Notes",
        "Source",
        "Window",
    ]

    while total_width() > available:
        changed = False
        for column in shrink_order:
            if column not in widths:
                continue
            minimum = max(len(column), 8)
            if widths[column] > minimum:
                widths[column] -= 1
                changed = True
                if total_width() <= available:
                    break
        if not changed:
            break

    def clip(value: str, width: int) -> str:
        if len(value) <= width:
            return value
        if width <= 1:
            return value[:width]
        return value[: width - 1] + "…"

    def align(column: str, value: str) -> str:
        clipped = clip(value, widths[column])
        if column in numeric_columns:
            return clipped.rjust(widths[column])
        return clipped.ljust(widths[column])

    header = " │ ".join(
        column.center(widths[column])
        for column in columns
    )
    separator = "─┼─".join("─" * widths[column] for column in columns)
    lines = [header, separator]

    for record in records:
        cells: list[str] = []
        for column in columns:
            value = str(record.get(column, ""))
            padded = align(column, value)
            color = color_for_column(column, value)
            cells.append(colorize(padded, color) if color else padded)
        lines.append(" │ ".join(cells))

    return "\n".join(lines)

def records_for_export(cards: Sequence[DecodedCard], detail: bool, only_valid: bool) -> list[dict[str, object]]:
    return [card_to_record(card, detail) for card in filter_cards(cards, only_valid)]


def write_csv(records: Sequence[dict[str, object]], stream: io.TextIOBase) -> None:
    if not records:
        return
    writer = csv.DictWriter(stream, fieldnames=list(records[0].keys()))
    writer.writeheader()
    writer.writerows(records)


def render_json(cards: Sequence[DecodedCard], only_valid: bool) -> str:
    payload = [asdict(card) for card in filter_cards(cards, only_valid)]
    return json.dumps(payload, indent=2)


def render_markdown(records: Sequence[dict[str, object]]) -> str:
    if not records:
        return "No rows to display."
    columns = list(records[0].keys())
    escape = lambda value: str(value).replace("|", "\\|")
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    lines.extend("| " + " | ".join(escape(record.get(col, "")) for col in columns) + " |" for record in records)
    return "\n".join(lines)


def stats_text(cards: Sequence[DecodedCard], elapsed: float | None = None) -> str:
    valid = [card for card in cards if card.valid]
    invalid = len(cards) - len(valid)
    parity_pass = sum(card.parity_ok is True for card in valid)
    parity_fail = sum(card.parity_ok is False for card in valid)
    counts = {
        bits: sum(card.bit_length == bits for card in valid)
        for bits in FORMATS
    }

    unique_count = len({
        (card.bit_length, card.facility_code, card.card_number)
        for card in valid
    })
    duplicate_count = max(0, len(valid) - unique_count)

    values: list[tuple[str, object, str | None]] = [
        ("Total Captures", len(cards), None),
        ("Valid Cards", len(valid), GREEN),
        ("Invalid Cards", invalid, RED if invalid else GREEN),
        ("Unique Cards", unique_count, CYAN),
        ("Duplicates", duplicate_count, YELLOW if duplicate_count else GREEN),
        ("Parity PASS", parity_pass, GREEN),
        ("Parity FAIL", parity_fail, YELLOW if parity_fail else GREEN),
    ]

    values.extend(
        (f"{bits}-bit", count, CYAN)
        for bits, count in counts.items()
        if count
    )

    if elapsed is not None:
        values.append(("Completed", f"{elapsed:.2f} sec", GRAY))

    label_width = max(len(label) for label, _, _ in values)
    value_width = max(len(str(value)) for _, value, _ in values)

    lines = [colorize("Statistics", WHITE_BOLD)]
    for label, value, value_color in values:
        colored_label = colorize(label.ljust(label_width), WHITE_BOLD)
        value_text = str(value).rjust(value_width)
        colored_value = colorize(value_text, value_color) if value_color else value_text
        lines.append(f"{colored_label} : {colored_value}")

    return "\n".join(lines)

def verbose_text(capture: Capture, card: DecodedCard, candidates: Sequence[Candidate]) -> str:
    width = 56
    def section(title: str) -> str:
        pad = max(2, width - len(title) - 2)
        left = pad // 2
        right = pad - left
        return f"{'═' * left} {title} {'═' * right}"

    lines = ["", section(f"Loot {capture.loot}"), "", "Capture", "───────"]
    lines.append(f"Source line   : {capture.source_line or 'N/A'}")
    lines.append(f"Reported bits : {capture.reported_bits or 'N/A'}")
    lines.append(f"Raw HEX       : {capture.raw_hex or 'N/A'}")
    lines.append(f"Binary length : {len(capture.binary) if capture.binary else 'N/A'}")

    if not card.valid:
        lines.extend(["", "Decode", "──────", f"Result        : Invalid ({card.reason})", "", "═" * width])
        return "\n".join(lines)

    lines.extend([
        "", "Decode", "──────",
        f"Detected      : {card.card_type}",
        f"Window        : {card.window} ({card.source})",
        f"Wiegand Bits  : {card.payload_bits}",
        f"Facility      : {card.facility_code}",
        f"Card number   : {card.card_number}",
        f"Parity        : {'PASS' if card.parity_ok else 'FAIL'}",
        f"Confidence    : {card.confidence}%",
        f"Flipper Hex   : {card.payload_data or 'N/A (HID 10301 / 26-bit only)'}",
    ])
    if candidates:
        lines.extend(["", "Top candidates", "──────────────"])
        for index, candidate in enumerate(candidates[:5], start=1):
            lines.append(
                f"{index}. {candidate.card_type} window {candidate.window_start}-{candidate.window_end} "
                f"source={candidate.source} parity={'PASS' if candidate.parity_ok else 'FAIL'} "
                f"range={'PASS' if candidate.fc_in_range and candidate.cn_in_range else 'FAIL'} "
                f"FC={candidate.facility_code} CN={candidate.card_number} score={candidate.score}"
            )
    lines.extend(["", "═" * width])
    return "\n".join(lines)


def create_manifest_zip(
    cards: Sequence[DecodedCard],
    output: Path,
    detail: bool,
    only_valid: bool,
    overwrite: bool,
) -> None:
    if output.exists() and not overwrite:
        raise RuntimeError(f"Output exists: {output}. Use --overwrite to replace it.")
    output.parent.mkdir(parents=True, exist_ok=True)

    selected = filter_cards(cards, only_valid)
    records = records_for_export(selected, detail=True, only_valid=False)
    csv_buffer = io.StringIO()
    write_csv(records, csv_buffer)
    json_text = json.dumps([asdict(card) for card in selected], indent=2)
    readme = (
        "Flipper HIDecoder inventory archive\n"
        f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
        f"Version: {VERSION}\n"
        f"Records: {len(selected)}\n\n"
        "This archive contains analysis manifests only; it does not contain\n"
        "credential-emulation files.\n"
    )

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.csv", csv_buffer.getvalue())
        archive.writestr("manifest.json", json_text)
        archive.writestr("README.txt", readme)



def export_all_credentials(
    cards: Sequence[DecodedCard],
    output_dir: Path,
) -> dict[str, object]:
    """Export redacted H10301 templates and inventory manifests.

    The generated .rfid.template files preserve the Flipper file structure
    but redact the Data field. No emulation-ready credential data is written.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    valid_cards = [card for card in cards if card.valid]
    h10301_cards = [
        card for card in valid_cards
        if card.bit_length == 26 and card.card_type == "HID H10301"
    ]

    manifest: list[dict[str, object]] = []
    created_files: list[str] = []

    for index, card in enumerate(h10301_cards, start=1):
        filename = (
            f"H10301_FC{card.facility_code}_CN{card.card_number}_{index}"
            ".rfid.template"
        )
        template_path = output_dir / filename
        template_lines = [
            "Filetype: Flipper RFID Key",
            "Version: 1",
            "Key type: H10301",
            "Data: XX XX XX",
            f"# PM3 Hex: {card.raw_hex}",
            f"# Facility Code: {card.facility_code}",
            f"# Card Number: {card.card_number}",
            "# Redacted template: no emulation-ready credential data included.",
            "",
        ]
        template_path.write_text(
            "\n".join(template_lines),
            encoding="utf-8",
        )
        created_files.append(filename)

    for card in valid_cards:
        manifest.append({
            "Loot": card.loot,
            "Bit": card.bit_length,
            "Card Type": card.card_type,
            "PM3 Hex": card.raw_hex,
            "FC": card.facility_code,
            "CN": card.card_number,
            "Flipper Hex": "REDACTED" if card.bit_length == 26 else "N/A",
            "Template Created": (
                "Yes"
                if card.bit_length == 26 and card.card_type == "HID H10301"
                else "No"
            ),
        })

    csv_path = output_dir / "manifest.csv"
    json_path = output_dir / "manifest.json"
    readme_path = output_dir / "README.txt"

    fields = [
        "Loot",
        "Bit",
        "Card Type",
        "PM3 Hex",
        "FC",
        "CN",
        "Flipper Hex",
        "Template Created",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(manifest)

    json_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    readme_path.write_text(
        "\n".join([
            "Flipper HIDecoder export-all inventory",
            f"Version: {VERSION}",
            "",
            "This directory contains redacted .rfid.template files",
            "and CSV/JSON inventory manifests.",
            "No emulation-ready credential data is included.",
            "",
        ]),
        encoding="utf-8",
    )

    return {
        "output_dir": str(output_dir),
        "valid_cards": len(valid_cards),
        "h10301_templates": len(created_files),
        "skipped_other_formats": len(valid_cards) - len(h10301_cards),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    description = """Flipper HIDecoder v3.2.5

Decode authorized ESP-RFID Tool / Proxmark3 HEX captures into
facility codes, card numbers, parity results, and Flipper-style HEX.
"""

    epilog = """Examples:
  %(prog)s --pm3 2004420A73
  %(prog)s --loot loot.txt
  %(prog)s --loot loot.txt --detail --stats
  %(prog)s --loot loot.txt --csv > cards.csv
  %(prog)s --loot loot.txt --json --output cards.json
  %(prog)s --loot loot.txt --export cards_inventory.zip
  %(prog)s --pm3 2004420A73 --verbose

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
"""

    parser = argparse.ArgumentParser(
        prog="FlipperHIDecoder.py",
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--pm3",
        "-pm3",
        "--raw",
        dest="raw",
        metavar="HEX",
        help="decode one Proxmark3/ESP-RFID hexadecimal capture",
    )
    source.add_argument(
        "--loot",
        "-l",
        "--log",
        dest="log",
        metavar="FILE",
        type=Path,
        help="parse an ESP-RFID loot/log file from line 3",
    )

    parser.add_argument(
        "--detail",
        action="store_true",
        help="add parity, Wiegand bits, window, source, and confidence",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="show capture and candidate-selection details",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="print a summary after the results",
    )
    parser.add_argument(
        "--only-valid",
        action="store_true",
        help="hide captures that could not be decoded",
    )

    parser.add_argument("--csv", action="store_true", help="write CSV to stdout")
    parser.add_argument("--json", action="store_true", help="write JSON")
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="write a Markdown table",
    )
    parser.add_argument(
        "--output",
        "-o",
        "--out",
        dest="out",
        metavar="FILE",
        type=Path,
        help="write the selected text format to a file",
    )

    export_group = parser.add_mutually_exclusive_group()
    export_group.add_argument(
        "--export",
        metavar="ZIP",
        type=Path,
        help="export valid-card CSV/JSON inventory manifests to a ZIP archive",
    )
    export_group.add_argument(
        "--zip-manifest",
        metavar="ZIP",
        type=Path,
        help=argparse.SUPPRESS,
    )

    parser.add_argument(
        "--export-all",
        metavar="DIR",
        dest="export_all",
        type=Path,
        help="export redacted H10301 .rfid templates and inventory manifests",
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace an existing output file",
    )
    parser.add_argument(
        "--no-fallback",
        action="store_true",
        help="do not try other lengths when the reported length is unusable",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="suppress the startup banner",
    )

    return parser

def choose_output_mode(args: argparse.Namespace) -> str:
    selected = [name for name in ("csv", "json", "markdown") if getattr(args, name)]
    if len(selected) > 1:
        raise RuntimeError("Choose only one of --csv, --json, or --markdown.")
    return selected[0] if selected else "table"


def write_text_output(text: str, path: Path, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise RuntimeError(f"Output exists: {path}. Use --overwrite to replace it.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    started = time.perf_counter()

    try:
        mode = choose_output_mode(args)
        terminal_mode = mode == "table" and not args.out

        if terminal_mode and not args.no_banner:
            print_banner()

        if args.log:
            captures = load_log(args.log)
        else:
            raw_value = args.raw
            if raw_value is None:
                try:
                    raw_value = input("Enter raw HEX: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nNo input provided.", file=sys.stderr)
                    return 1
            try:
                normalized = normalize_hex(raw_value)
            except ValueError as exc:
                print(f"Invalid raw HEX: {exc}", file=sys.stderr)
                return 2
            captures = [Capture(loot=1, raw_hex=normalized)]

        decoded: list[DecodedCard] = []
        candidate_sets: list[list[Candidate]] = []
        total = len(captures)
        for index, capture in enumerate(captures, start=1):
            card, candidates = decode_capture(capture, fallback_formats=not args.no_fallback)
            decoded.append(card)
            candidate_sets.append(candidates)

        if terminal_mode:
            valid_count = sum(card.valid for card in decoded)
            invalid_count = len(decoded) - valid_count
            capture_word = "capture" if len(decoded) == 1 else "captures"
            summary = f"Loaded {len(decoded)} {capture_word} ({valid_count} valid, {invalid_count} invalid)"
            symbol = "✓" if invalid_count == 0 else "[+]"
            print(f"{colorize(symbol, GREEN)} {summary}")
            print()

        records = records_for_export(decoded, args.detail, args.only_valid)
        if mode == "csv":
            buffer = io.StringIO()
            write_csv(records, buffer)
            text = buffer.getvalue().rstrip("\n")
        elif mode == "json":
            text = render_json(decoded, args.only_valid)
        elif mode == "markdown":
            text = render_markdown(records)
        else:
            text = render_table(decoded, args.detail, args.only_valid)

        if args.out:
            write_text_output(text, args.out, args.overwrite)
            status(f"Results written to {args.out}", "ok")
        else:
            print(text)
            if terminal_mode:
                print()

        if args.verbose:
            for capture, card, candidates in zip(captures, decoded, candidate_sets):
                print(verbose_text(capture, card, candidates))

        elapsed = time.perf_counter() - started
        if args.stats or terminal_mode:
            print()
            print(stats_text(decoded, elapsed))

        export_path = args.export or args.zip_manifest
        if export_path:
            create_manifest_zip(
                decoded,
                export_path,
                args.detail,
                args.only_valid,
                args.overwrite,
            )
            status(f"Inventory ZIP written to {export_path}", "ok")

        if args.export_all:
            export_result = export_all_credentials(decoded, args.export_all)
            status(
                f"Created {export_result['h10301_templates']} redacted "
                f"H10301 template(s) in {export_result['output_dir']}",
                "ok",
            )

        return 0
    except RuntimeError as exc:
        status(str(exc), "error")
        return 2
    except OSError as exc:
        status(f"File error: {exc}", "error")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


def export_all_credentials(cards, output_dir):
    """Export all supported credential formats.

    Current implementation:
      * HID H10301 (26-bit) -> .rfid
      * Other formats are skipped until native Flipper support is implemented.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    return {
        "exported_h10301": sum(
            1 for c in cards
            if getattr(c, "valid", False)
            and getattr(c, "format_bits", 0) == 26
        ),
        "skipped_other_formats": sum(
            1 for c in cards
            if getattr(c, "valid", False)
            and getattr(c, "format_bits", 0) != 26
        ),
    }
