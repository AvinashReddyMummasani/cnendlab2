#!/usr/bin/env python3
"""
pyshark_analyzer.py
====================
Computer Networks Assignment — Data Link Layer Packet Analyzer

This script attempts to capture live UDP packets via PyShark (Wireshark/TShark
back-end) from the C++ simulation running on localhost:9000.  If PyShark or
Wireshark is not installed it falls back gracefully to parsing the
`packet_log.txt` file written by the C++ simulation.

Installation (run once in your terminal):
    pip install pyshark colorama tabulate

C++ simulation must be running and writing packet_log.txt in the same directory.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Standard-library imports
# ─────────────────────────────────────────────────────────────────────────────
import json
import os
import sys
import time
import datetime
from pathlib import Path
from collections import defaultdict

# Ensure UTF-8 output on Windows consoles to avoid charmap UnicodeEncodeErrors
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# Optional dependency: PyShark
# Tries Windows loopback first, then generic 'lo' for Linux/macOS.
# Falls back to log-file parsing if unavailable.
# ─────────────────────────────────────────────────────────────────────────────
PYSHARK_AVAILABLE = False
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    print("[WARNING] PyShark is not installed (pip install pyshark).")
    print("          Falling back to packet_log.txt parsing.\n")

# ─────────────────────────────────────────────────────────────────────────────
# Monochrome / Clean plain-text formatting (no color codes)
# ─────────────────────────────────────────────────────────────────────────────
class _Dummy:
    def __getattr__(self, name):
        return ""

class _Style:
    RESET_ALL = ""
    BRIGHT    = ""
    DIM       = ""

Fore  = _Dummy()
Back  = _Dummy()
Style = _Style()

# ─────────────────────────────────────────────────────────────────────────────
# Table formatting helper (clean plain text fallback)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

    def tabulate(rows, headers=(), tablefmt="simple", **kwargs):
        """Minimal tabulate replacement — clean, aligned columns."""
        all_rows   = [headers] + list(rows) if headers else list(rows)
        col_widths = [0] * (len(all_rows[0]) if all_rows else 0)
        for row in all_rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        lines = []
        for idx, row in enumerate(all_rows):
            line = "  ".join(str(cell).ljust(col_widths[i])
                             for i, cell in enumerate(row))
            lines.append(line)
            if idx == 0 and headers:
                lines.append("-" * (sum(col_widths) + 2 * len(col_widths)))
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Constants & configuration
# ─────────────────────────────────────────────────────────────────────────────
LOG_FILE         = Path(__file__).parent / "packet_log.txt"
PCAP_FILE        = Path(__file__).parent / "packet_capture.pcap"
LOOPBACK_WIN     = r"\Device\NPF_Loopback"   # Wireshark loopback on Windows
LOOPBACK_UNIX    = "lo"                       # loopback on Linux / macOS
UDP_PORT         = 9000                       # port the C++ sim uses
WINDOW_SIZE      = 4                          # Go-Back-N window size (default)
SEPARATOR_WIDE   = "=" * 72
SEPARATOR_THIN   = "-" * 72


# ─────────────────────────────────────────────────────────────────────────────
# Plain-text display helpers (monochrome / simple)
# ─────────────────────────────────────────────────────────────────────────────
def c(text, *args, **kwargs):
    """Simple plain-text passthrough (no ANSI color codes)."""
    return str(text)


def banner(title: str, char: str = "=", width: int = 72) -> str:
    """Return a centred banner string."""
    pad   = max(0, (width - len(title) - 2) // 2)
    line  = char * pad + f" {title} " + char * pad
    line += char * max(0, width - len(line))
    return line


def section_header(title: str) -> None:
    """Print a prominent section header."""
    print()
    print(banner(title))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────
class Packet:
    """Represents a single frame from the simulation log / live capture."""

    def __init__(self, seq: int, pkt_type: str, sender: str, receiver: str,
                 data: str, hamming: str, error_bit: int, corrected: bool,
                 timestamp: str):
        self.seq        = seq
        self.type       = pkt_type          # RTS | CTS | DATA | ACK | NACK
        self.sender     = sender
        self.receiver   = receiver
        self.data       = data              # original binary payload
        self.hamming    = hamming           # Hamming-encoded bits
        self.error_bit  = error_bit         # -1 means no error
        self.corrected  = corrected
        self.timestamp  = timestamp

    # ── convenience properties ──────────────────────────────────────────────
    @property
    def has_error(self) -> bool:
        return self.error_bit != -1

    @property
    def is_data(self) -> bool:
        return self.type == "DATA"

    @property
    def is_control(self) -> bool:
        return self.type in {"RTS", "CTS", "ACK", "NACK"}

    def __repr__(self):
        return (f"Packet(seq={self.seq}, type={self.type}, "
                f"{self.sender}→{self.receiver})")


# ─────────────────────────────────────────────────────────────────────────────
# Log-file parser
# ─────────────────────────────────────────────────────────────────────────────
def parse_log_file(path: Path) -> list:
    """
    Parse every JSON line in *path* and return a list of Packet objects.
    Lines that are blank or cannot be decoded are skipped with a warning.
    """
    packets = []
    if not path.exists():
        print(c(f"[ERROR] Log file not found: {path}", Fore.RED, bright=True))
        print("        Run the C++ simulation first, or check the path.")
        return packets

    print(c(f"[INFO] Reading packets from: {path}", Fore.GREEN))
    with path.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                pkt = Packet(
                    seq       = int(obj.get("seq",       0)),
                    pkt_type  = str(obj.get("type",      "UNKNOWN")).upper(),
                    sender    = str(obj.get("sender",    "?")),
                    receiver  = str(obj.get("receiver",  "?")),
                    data      = str(obj.get("data",      "")),
                    hamming   = str(obj.get("hamming",   "")),
                    error_bit = int(obj.get("error_bit", -1)),
                    corrected = bool(obj.get("corrected", False)),
                    timestamp = str(obj.get("timestamp", "00:00:00.000")),
                )
                packets.append(pkt)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                print(c(f"[WARN] Line {lineno}: could not parse — {exc}",
                        Fore.YELLOW))

    print(c(f"[INFO] Loaded {len(packets)} packet(s).\n", Fore.GREEN))
    return packets


# ─────────────────────────────────────────────────────────────────────────────
# PyShark live-capture helper
# ─────────────────────────────────────────────────────────────────────────────
def parse_pyshark_packet(raw_pkt) -> Packet | None:
    """
    Convert a raw PyShark packet object into our Packet model.

    The C++ sim encodes the JSON payload as the UDP data field.
    We attempt to extract and decode it; on failure we return None.
    """
    try:
        # UDP payload is available as a hex string in the 'data' layer
        if not hasattr(raw_pkt, "data"):
            return None
        hex_data = raw_pkt.data.data.replace(":", "")
        payload  = bytes.fromhex(hex_data).decode("utf-8").strip()
        obj      = json.loads(payload)
        return Packet(
            seq       = int(obj.get("seq",       0)),
            pkt_type  = str(obj.get("type",      "UNKNOWN")).upper(),
            sender    = str(obj.get("sender",    "?")),
            receiver  = str(obj.get("receiver",  "?")),
            data      = str(obj.get("data",      "")),
            hamming   = str(obj.get("hamming",   "")),
            error_bit = int(obj.get("error_bit", -1)),
            corrected = bool(obj.get("corrected", False)),
            timestamp = str(obj.get("timestamp",
                                    str(datetime.datetime.now().time()))),
        )
    except Exception:
        return None


def capture_live_packets(timeout: int = 10) -> list:
    """
    Use PyShark to capture UDP packets on the loopback interface for
    *timeout* seconds.  Returns a list of Packet objects.

    On Windows the loopback interface name for WinPcap/Npcap is
    r'\\Device\\NPF_Loopback'.  We try that first, then fall back to 'lo'.
    """
    packets     = []
    interfaces  = [LOOPBACK_WIN, LOOPBACK_UNIX]

    for iface in interfaces:
        try:
            print(c(f"[PyShark] Trying interface: {iface}", Fore.CYAN))
            capture = pyshark.LiveCapture(
                interface    = iface,
                display_filter = f"udp.port == {UDP_PORT}",
            )
            # sniff_continuously for *timeout* seconds
            capture.sniff(timeout=timeout)
            for raw_pkt in capture:
                pkt = parse_pyshark_packet(raw_pkt)
                if pkt:
                    packets.append(pkt)
            if packets:
                print(c(f"[PyShark] Captured {len(packets)} packet(s) on "
                        f"'{iface}'.\n", Fore.GREEN))
                return packets
        except Exception as exc:
            print(c(f"[PyShark] Interface '{iface}' failed: {exc}", Fore.YELLOW))

    print(c("[PyShark] Live capture unsuccessful — "
            "falling back to log/pcap file.\n", Fore.YELLOW))
    return []


def parse_pcap_file(pcap_path: Path) -> list:
    """
    Use PyShark to read and dissect packets from the PCAP capture file.
    Extracts Ethernet, IPv4, UDP, and custom Data Link payload layers.
    Returns a list of Packet objects.
    """
    packets = []
    if not pcap_path.exists():
        return packets

    try:
        print(c(f"[PyShark] Reading captured packets via PyShark/TShark from: {pcap_path}", Fore.GREEN))
        cap = pyshark.FileCapture(str(pcap_path))
        for raw_pkt in cap:
            pkt = parse_pyshark_packet(raw_pkt)
            if pkt:
                packets.append(pkt)
        cap.close()
        if packets:
            print(c(f"[PyShark] Successfully analyzed {len(packets)} packet(s) via PyShark.\n",
                    Fore.GREEN, bright=True))
            return packets
    except Exception as exc:
        print(c(f"[PyShark] PCAP file reading failed ({exc}) — falling back to log file.\n", Fore.YELLOW))

    return packets


# ─────────────────────────────────────────────────────────────────────────────
# Wireshark-style packet dissection display
# ─────────────────────────────────────────────────────────────────────────────
TYPE_COLOURS = {
    "RTS"  : Fore.MAGENTA,
    "CTS"  : Fore.BLUE,
    "DATA" : Fore.WHITE,
    "ACK"  : Fore.GREEN,
    "NACK" : Fore.RED,
}


def dissect_packet(pkt: Packet) -> None:
    """
    Print a Wireshark-style dissection panel for a single packet.

    Frame
    └─ Simulation Layer (CSMA/CA)
       └─ Go-Back-N Transport
          └─ Data / Hamming payload
    """
    col  = TYPE_COLOURS.get(pkt.type, Fore.WHITE)
    err_flag = (c("⚠ ERROR INJECTED", Fore.RED, bright=True)
                if pkt.has_error else c("✔ clean", Fore.GREEN))
    corr_flag = (c("✔ CORRECTED", Fore.GREEN, bright=True)
                 if pkt.corrected else "")

    print(c(SEPARATOR_THIN, Fore.WHITE))
    # ── Frame header ────────────────────────────────────────────────────────
    print(c(f"  Frame {pkt.seq:>3}  │  {pkt.timestamp}  │  "
            f"{pkt.sender} → {pkt.receiver}  │  "
            f"Type: ", Fore.WHITE) +
          c(f"{pkt.type:<6}", col, bright=True))

    # ── Simulation (CSMA/CA) layer ──────────────────────────────────────────
    print(c("  ├─ [Simulation / CSMA-CA Layer]", Fore.CYAN))
    print(c(f"  │    Sequence number : {pkt.seq}", Fore.CYAN))
    print(c(f"  │    Frame type      : {pkt.type}", col))
    print(c(f"  │    Sender          : {pkt.sender}", Fore.CYAN))
    print(c(f"  │    Receiver        : {pkt.receiver}", Fore.CYAN))

    # ── Go-Back-N layer (DATA frames only) ──────────────────────────────────
    if pkt.is_data:
        print(c("  ├─ [Go-Back-N Transport Layer]", Fore.YELLOW))
        print(c(f"  │    Sequence #      : {pkt.seq}", Fore.YELLOW))
        print(c(f"  │    Payload (bin)   : {pkt.data or '<empty>'}", Fore.YELLOW))
        print(c(f"  │    Error status    : {err_flag}", Fore.YELLOW) +
              ("  " + corr_flag if pkt.corrected else ""))

    # ── Hamming layer (DATA frames only) ────────────────────────────────────
    if pkt.is_data and pkt.hamming:
        print(c("  └─ [Hamming ECC Layer]", Fore.MAGENTA))
        print(c(f"       Original bits   : {pkt.data}", Fore.MAGENTA))
        print(c(f"       Encoded bits    : {pkt.hamming}", Fore.MAGENTA))
        if pkt.has_error:
            # Show which bit position is flipped
            bits = list(pkt.hamming)
            pos  = pkt.error_bit           # 1-indexed per Hamming convention
            marked = ""
            for i, b in enumerate(bits):
                if i + 1 == pos:           # 1-indexed → 0-indexed
                    marked += c(b, Fore.RED, bright=True)
                else:
                    marked += c(b, Fore.MAGENTA)
            print(c(f"       Error bit pos   : {pos}  (bit flipped below)",
                    Fore.RED))
            print(f"       Received bits   : {marked}")
            print(c(f"       Corrected       : {pkt.corrected}",
                    Fore.GREEN if pkt.corrected else Fore.RED))
        else:
            print(c("       No errors detected.", Fore.GREEN))

    # ── Control frames — short note ─────────────────────────────────────────
    if pkt.is_control and pkt.type not in {"DATA"}:
        note = {
            "RTS" : "Request To Send — node claiming the channel",
            "CTS" : "Clear To Send   — channel granted by receiver",
            "ACK" : "Acknowledgement — frame received successfully",
            "NACK": "Negative ACK    — error detected, retransmit requested",
        }.get(pkt.type, "")
        print(c(f"  └─ [Control Info] {note}", Fore.CYAN))


# ─────────────────────────────────────────────────────────────────────────────
# Section 1 — CSMA/CA channel negotiation flow
# ─────────────────────────────────────────────────────────────────────────────
def display_csma_ca_section(packets: list) -> dict:
    """
    Filter and display all CSMA/CA control frames (RTS, CTS, ACK, NACK).
    Returns a stats dict for the final summary.
    """
    section_header("SECTION 1 — CSMA/CA Channel Negotiation Flow")

    control_pkts = [p for p in packets if p.type in {"RTS", "CTS", "ACK", "NACK"}]
    stats = {
        "rts"         : 0,
        "cts"         : 0,
        "ack"         : 0,
        "nack"        : 0,
        "collisions_avoided": 0,  # each RTS/CTS pair = 1 avoided collision
    }

    if not control_pkts:
        print(c("  No CSMA/CA control frames found.", Fore.YELLOW))
        return stats

    # ── Timeline table ───────────────────────────────────────────────────────
    rows = []
    for p in control_pkts:
        col = TYPE_COLOURS.get(p.type, Fore.WHITE)
        rows.append([
            p.timestamp,
            p.seq,
            c(p.type, col, bright=True),
            p.sender,
            p.receiver,
            c("channel request",   Fore.MAGENTA) if p.type == "RTS"  else
            c("channel granted",   Fore.BLUE)    if p.type == "CTS"  else
            c("delivery OK",       Fore.GREEN)   if p.type == "ACK"  else
            c("retransmit needed", Fore.RED),
        ])
        stats[p.type.lower()] = stats.get(p.type.lower(), 0) + 1

    headers = ["Timestamp", "Seq#", "Type", "Sender", "Receiver", "Meaning"]
    print(tabulate(rows, headers=headers, tablefmt="fancy_grid"))

    # ── Sequence diagram ─────────────────────────────────────────────────────
    print()
    print(c("  Channel Negotiation Sequence:", Fore.CYAN, bright=True))
    print()
    prev_type = None
    for p in control_pkts:
        arrow = "  ─────────────────────────────▶  " if p.sender < p.receiver else \
                "  ◀─────────────────────────────  "
        col   = TYPE_COLOURS.get(p.type, Fore.WHITE)
        line  = (f"  {c(p.sender, Fore.WHITE, bright=True):<10}"
                 f"{c(arrow + p.type, col)}"
                 f"  {c(p.receiver, Fore.WHITE, bright=True)}"
                 f"  [{p.timestamp}]")
        # Draw a blank separator between RTS→CTS pairs to show DIFS/SIFS slots
        if prev_type == "CTS" and p.type == "RTS":
            print(c("  " + "·" * 60 + "  (DIFS gap)", Fore.WHITE))
        print(line)
        prev_type = p.type

    # Count RTS/CTS pairs → collisions avoided (each handshake blocks others)
    stats["collisions_avoided"] = min(stats["rts"], stats["cts"])
    print()
    print(c(f"  ✔ {stats['collisions_avoided']} potential collision(s) avoided "
            f"via RTS/CTS handshake.", Fore.GREEN, bright=True))

    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Section 2 — Go-Back-N sliding window
# ─────────────────────────────────────────────────────────────────────────────
def display_gbn_section(packets: list, window_size: int = WINDOW_SIZE) -> dict:
    """
    Track the Go-Back-N sliding window state as DATA / ACK / NACK frames
    arrive and print a visual window diagram for each event.
    Returns retransmission stats.
    """
    section_header("SECTION 2 — Go-Back-N Sliding Window")

    data_pkts  = [p for p in packets if p.is_data or p.type in {"ACK", "NACK"}]
    stats      = {"data_sent": 0, "acks": 0, "nacks": 0, "retransmissions": 0}

    if not data_pkts:
        print(c("  No DATA/ACK/NACK frames found.", Fore.YELLOW))
        return stats

    # ── State tracking ───────────────────────────────────────────────────────
    send_base   = 0          # oldest unacknowledged sequence number
    next_seq    = 0          # next sequence number to assign
    window      = []         # currently in-flight seq numbers
    nack_seq    = set()      # sequences that triggered retransmit

    print(c(f"  Window size (N) = {window_size}\n", Fore.YELLOW, bright=True))
    print(c("  Legend:  [  ] = empty slot  |  [##] = in-flight  |  "
            "[OK] = acked  |  [!!] = NACK\n", Fore.WHITE))

    def draw_window(highlight_seq=None, nacked=False, label=""):
        """Print a single-row sliding-window diagram."""
        bar = ""
        for i in range(send_base, send_base + window_size):
            if i == highlight_seq and nacked:
                slot = c(f"[{i:02d}✗]", Fore.RED, bright=True)
            elif i == highlight_seq:
                slot = c(f"[{i:02d}→]", Fore.YELLOW, bright=True)
            elif i < next_seq:
                slot = c(f"[{i:02d}✓]", Fore.GREEN)
            elif i in window:
                slot = c(f"[{i:02d}··]", Fore.CYAN)
            else:
                slot = c(f"[{i:02d}  ]", Fore.WHITE)
            bar += slot
        tag = f"  base={send_base}  next={next_seq}"
        print(f"  Window ▶ {bar}  {c(tag, Fore.WHITE)}  {label}")

    # ── Walk through events ──────────────────────────────────────────────────
    for p in data_pkts:
        if p.is_data:
            stats["data_sent"] += 1
            window.append(p.seq)
            next_seq = max(next_seq, p.seq + 1)
            label = c(f"DATA seq={p.seq} sent  {p.sender}→{p.receiver}",
                      Fore.WHITE)
            draw_window(highlight_seq=p.seq, label=label)
            # dissect packet inline
            dissect_packet(p)

        elif p.type == "ACK":
            stats["acks"] += 1
            # Cumulative ACK: slide window up to and including this seq
            if p.seq in window:
                window = [s for s in window if s > p.seq]
                send_base = p.seq + 1
            label = c(f"ACK seq={p.seq}  window slides → base={send_base}",
                      Fore.GREEN)
            draw_window(highlight_seq=p.seq, label=label)

        elif p.type == "NACK":
            stats["nacks"] += 1
            # Go-Back-N: roll back to the NACK'd sequence
            if p.seq not in nack_seq:
                nack_seq.add(p.seq)
                stats["retransmissions"] += 1
                # Reset window to the NAK'd position
                send_base = p.seq
                window    = [s for s in window if s >= p.seq]
                next_seq  = p.seq
            label = c(f"NACK seq={p.seq}  ← ROLLBACK  retransmit from {p.seq}",
                      Fore.RED, bright=True)
            draw_window(highlight_seq=p.seq, nacked=True, label=label)

        print()

    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Section 3 — Hamming code analysis
# ─────────────────────────────────────────────────────────────────────────────
def display_hamming_section(packets: list) -> dict:
    """
    For every DATA frame show the full Hamming encoding pipeline:
    original → parity-bit positions → encoded → received (with error mark)
    → corrected bit.
    """
    section_header("SECTION 3 — Hamming Code Error Analysis")

    data_pkts = [p for p in packets if p.is_data and p.hamming]
    stats     = {"data_frames": 0, "errors_detected": 0, "errors_corrected": 0}

    if not data_pkts:
        print(c("  No DATA frames with Hamming encoding found.", Fore.YELLOW))
        return stats

    for p in data_pkts:
        stats["data_frames"] += 1
        col = Fore.RED if p.has_error else Fore.GREEN

        print(c(SEPARATOR_THIN, Fore.WHITE))
        print(c(f"  Frame seq={p.seq}  │  {p.sender} → {p.receiver}  "
                f"│  {p.timestamp}", Fore.WHITE, bright=True))
        print()

        # ── Step 1: Original data bits ────────────────────────────────────
        print(c("  ┌─ Step 1 │ Original (raw) data bits:", Fore.CYAN))
        bits_display = " ".join(b for b in p.data) if p.data else "<none>"
        print(c(f"  │         │ {bits_display}", Fore.WHITE))
        print(c(f"  │         │ Length = {len(p.data)} bit(s)", Fore.WHITE))

        # ── Step 2: Hamming-encoded bits ──────────────────────────────────
        print(c("  ├─ Step 2 │ Hamming-encoded bits:", Fore.CYAN))
        enc_display = " ".join(b for b in p.hamming)
        print(c(f"  │         │ {enc_display}", Fore.MAGENTA))
        print(c(f"  │         │ Length = {len(p.hamming)} bit(s)  "
                f"(data + parity bits)", Fore.WHITE))

        # ── Step 3: Parity-bit positions ──────────────────────────────────
        n       = len(p.hamming)
        r       = 0
        while (1 << r) < n + 1:
            r += 1
        parity_positions = [1 << i for i in range(r) if (1 << i) <= n]
        print(c("  ├─ Step 3 │ Parity bit positions (1-indexed):", Fore.CYAN))
        print(c(f"  │         │ {parity_positions}", Fore.WHITE))

        # ── Step 4: Received bits (error injection) ───────────────────────
        print(c("  ├─ Step 4 │ Received bits (after transmission):", Fore.CYAN))
        received_bits = list(p.hamming)
        if p.has_error and 1 <= p.error_bit <= len(received_bits):
            # Flip the error bit to show what was received
            idx = p.error_bit - 1     # 1-indexed → 0-indexed
            received_bits[idx] = "1" if received_bits[idx] == "0" else "0"

        recv_display = ""
        for i, b in enumerate(received_bits):
            pos = i + 1   # 1-indexed
            if p.has_error and pos == p.error_bit:
                recv_display += c(b, Fore.RED, bright=True) + " "
            elif pos in parity_positions:
                recv_display += c(b, Fore.YELLOW) + " "
            else:
                recv_display += c(b, Fore.WHITE) + " "

        print(f"  │         │ {recv_display.rstrip()}")

        if p.has_error:
            stats["errors_detected"] += 1
            print(c(f"  │         │ ⚠ Error detected at bit position "
                    f"{p.error_bit}  (1-indexed from MSB)",
                    Fore.RED, bright=True))
        else:
            print(c("  │         │ ✔ No errors in received bits.", Fore.GREEN))

        # ── Step 5: Error correction ──────────────────────────────────────
        print(c("  └─ Step 5 │ Error correction result:", Fore.CYAN))
        if p.has_error:
            if p.corrected:
                stats["errors_corrected"] += 1
                # Show corrected bits (same as original encoded)
                corr_display = " ".join(b for b in p.hamming)
                print(c(f"            │ Corrected bits : {corr_display}",
                        Fore.GREEN))
                print(c("            │ ✔ Single-bit error corrected "
                        "successfully via Hamming SEC.", Fore.GREEN, bright=True))
            else:
                print(c("            │ ✘ Error NOT corrected "
                        "(possible multi-bit error or uncorrectable).",
                        Fore.RED, bright=True))
        else:
            print(c("            │ ✔ No correction needed.", Fore.GREEN))
        print()

    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────────────────────────────────────
def display_summary(packets: list,
                    csma_stats: dict,
                    gbn_stats: dict,
                    hamming_stats: dict) -> None:
    """Print a consolidated summary table of all protocol metrics."""
    section_header("FINAL SUMMARY")

    total       = len(packets)
    sent        = sum(1 for p in packets if p.type in {"RTS", "DATA"})
    received    = sum(1 for p in packets if p.type in {"ACK", "CTS"})
    data_frames = gbn_stats["data_sent"]
    errors      = hamming_stats["errors_detected"]
    corrected   = hamming_stats["errors_corrected"]
    retrans     = gbn_stats["retransmissions"]
    collisions  = csma_stats["collisions_avoided"]

    rows = [
        ["Total frames captured",          c(str(total),      Fore.WHITE, bright=True)],
        ["Frames sent (RTS + DATA)",        c(str(sent),       Fore.CYAN)],
        ["Frames received (CTS + ACK)",     c(str(received),   Fore.GREEN)],
        ["DATA frames",                     c(str(data_frames),Fore.WHITE)],
        ["RTS frames",                      c(str(csma_stats["rts"]),  Fore.MAGENTA)],
        ["CTS frames",                      c(str(csma_stats["cts"]),  Fore.BLUE)],
        ["ACK frames",                      c(str(csma_stats["ack"]),  Fore.GREEN)],
        ["NACK frames",                     c(str(csma_stats["nack"]), Fore.RED)],
        ["Errors detected (Hamming)",       c(str(errors),     Fore.RED, bright=True)],
        ["Errors corrected (Hamming SEC)",  c(str(corrected),  Fore.GREEN, bright=True)],
        ["Retransmissions (Go-Back-N)",     c(str(retrans),    Fore.YELLOW, bright=True)],
        ["Collisions avoided (CSMA/CA)",    c(str(collisions), Fore.CYAN, bright=True)],
    ]

    print(tabulate(rows, headers=["Metric", "Value"], tablefmt="fancy_grid"))
    print()

    # ── Pass/Fail assessment ─────────────────────────────────────────────────
    all_corrected = errors == corrected
    print(c("  ┌─ Assessment ──────────────────────────────────────────────┐",
            Fore.CYAN))
    if errors == 0:
        print(c("  │  ✔ All transmissions were error-free.                    │",
                Fore.GREEN, bright=True))
    elif all_corrected:
        print(c(f"  │  ✔ All {errors} error(s) were detected and corrected "
                f"by Hamming SEC.  │", Fore.GREEN, bright=True))
    else:
        uncorr = errors - corrected
        print(c(f"  │  ⚠ {uncorr} error(s) were NOT corrected "
                f"(multi-bit or uncorrectable).  │", Fore.RED, bright=True))
    if retrans > 0:
        print(c(f"  │  ↺ {retrans} retransmission(s) performed by Go-Back-N ARQ. "
                f"              │", Fore.YELLOW))
    if collisions > 0:
        print(c(f"  │  ✔ {collisions} collision(s) avoided via CSMA/CA RTS/CTS.  "
                f"                │", Fore.CYAN))
    print(c("  └──────────────────────────────────────────────────────────┘",
            Fore.CYAN))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print()
    print(banner("DATA LINK LAYER PACKET ANALYZER", char="="))
    print("  Computer Networks -- CSMA/CA  |  Go-Back-N  |  Hamming ECC")
    print(c(f"  Analyzed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            Fore.WHITE))
    print()

    # ── Step 1: Acquire packets ──────────────────────────────────────────────
    packets: list = []

    live_mode = "--live" in sys.argv

    if live_mode and PYSHARK_AVAILABLE:
        print(c("[INFO] Live capture mode requested — listening on loopback "
                f"({UDP_PORT}/udp, 10 s)...", Fore.GREEN))
        packets = capture_live_packets(timeout=10)

    # If not live mode or live capture returned nothing, dissect PCAP via PyShark
    if not packets and PYSHARK_AVAILABLE and PCAP_FILE.exists():
        print(c("[INFO] PyShark available — loading PCAP capture file for deep packet inspection...", Fore.CYAN))
        packets = parse_pcap_file(PCAP_FILE)

    # Fallback to packet_log.txt if PCAP not available or returned nothing
    if not packets:
        packets = parse_log_file(LOG_FILE)

    if not packets:
        print(c("[ERROR] No packets to analyze. "
                "Ensure packet_log.txt exists or the C++ sim is running.",
                Fore.RED, bright=True))
        sys.exit(1)

    # ── Step 2: Run analysis sections ────────────────────────────────────────
    csma_stats    = display_csma_ca_section(packets)
    gbn_stats     = display_gbn_section(packets)
    hamming_stats = display_hamming_section(packets)

    # ── Step 3: Print final summary ──────────────────────────────────────────
    display_summary(packets, csma_stats, gbn_stats, hamming_stats)


if __name__ == "__main__":
    main()
