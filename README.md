# Data Link Layer Simulation
### End Assignment 8 — Computer Networks (Sem 5)

> A unified simulation of the **Data Link Layer** combining CSMA/CA (Multiple Access), Go-Back-N ARQ (Flow Control), and Hamming Code (Error Control), implemented in C++ with a Python PyShark packet analyzer.

---

## Table of Contents

1. [What Was Done](#1-what-was-done)
   - [System Architecture](#system-architecture)
   - [Component Overview](#component-overview)
   - [How to Compile and Run](#how-to-compile-and-run)
2. [Concepts Used & Surrounding Theory](#2-concepts-used--surrounding-theory)
   - [Data Link Layer Overview](#data-link-layer-overview)
   - [Framing](#framing)
   - [Error Control — Hamming Code](#error-control--hamming-code)
   - [Flow Control — Go-Back-N ARQ](#flow-control--go-back-n-arq)
   - [Multiple Access — CSMA/CA](#multiple-access--csmaca)
3. [Example Dry Run](#3-example-dry-run)
4. [References](#4-references)

---

## 1. What Was Done

This project simulates the **Data Link Layer** of the OSI model by combining three core mechanisms into a single, cohesive pipeline:

| Layer Mechanism | Protocol/Algorithm | Purpose |
|---|---|---|
| Multiple Access (MAC) | **CSMA/CA** with RTS/CTS | Prevent collisions on a shared wireless channel |
| Flow Control | **Go-Back-N ARQ** (Window=4) | Reliable, in-order delivery with sliding window |
| Error Control | **Hamming Code** (SEC) | Detect and correct single-bit errors in frames |

### System Architecture

The simulation models two data nodes (Node A and Node C) competing for a shared wireless channel to communicate with Node B. Every data frame passes through all three layers of protocol:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DATA LINK LAYER SIMULATION                        │
│                                                                       │
│  Node A                   Channel                   Node B           │
│  ──────                   ───────                   ──────           │
│    │                         │                         │             │
│    │──── CSMA/CA Phase ──────│                         │             │
│    │   [Sense channel: IDLE] │                         │             │
│    │──── RTS ───────────────▶│                         │             │
│    │                         │◀─── CTS ────────────────│             │
│    │   (NAV set; Node C      │                         │             │
│    │    defers transmission) │                         │             │
│    │                         │                         │             │
│    │──── Go-Back-N Phase ────┼─────────────────────────│             │
│    │   Window = [0,1,2,3]    │                         │             │
│    │──── DATA[0] ───────────▶│────────────────────────▶│             │
│    │   (Hamming encoded)     │                         │── ACK[0] ──▶│
│    │──── DATA[1] ───────────▶│────────────────────────▶│             │
│    │──── DATA[2] ───────────▶│────────────────────────▶│ (error!)    │
│    │                         │             [Hamming corrects error]   │
│    │                         │                         │── ACK[2] ──▶│
│    │──── DATA[3] ───────────▶│   ✗ LOST (timeout!)     │             │
│    │   ◀─── TIMEOUT ─────────│                         │             │
│    │   [Rollback to seq=3]   │                         │             │
│    │──── DATA[3] ───────────▶│────────────────────────▶│             │
│    │──── DATA[4] ───────────▶│────────────────────────▶│             │
│    │──── DATA[5] ───────────▶│────────────────────────▶│             │
│    │                         │                         │             │
│  Node C (deferred)          │                         │             │
│  ──────                     │                         │             │
│    │──── CSMA/CA Phase ──────│                         │             │
│    │   [Sense channel: IDLE] │                         │             │
│    │──── RTS ───────────────▶│◀─── CTS ────────────────│             │
│    │──── DATA[0,1] ─────────▶│────────────────────────▶│             │
│    │                         │                         │             │
└─────────────────────────────────────────────────────────────────────┘
```

#### Unified Data Flow (Per Frame)

```
Application Data
       │
       ▼
┌──────────────────┐
│  Hamming Encode  │  ← Add parity bits (r bits for m data bits)
│  (Error Control) │
└────────┬─────────┘
         │  Encoded Frame (m + r bits)
         ▼
┌──────────────────┐
│  Go-Back-N ARQ   │  ← Assign sequence number, manage sliding window
│  (Flow Control)  │
└────────┬─────────┘
         │  Numbered Frame
         ▼
┌──────────────────┐
│    CSMA/CA       │  ← Sense channel → RTS/CTS → Transmit
│  (MAC / Access)  │
└────────┬─────────┘
         │
    [ Wireless Channel ]
         │
         ▼
┌──────────────────┐
│   CSMA/CA Recv   │  ← Receive after CTS grant
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Go-Back-N Recv  │  ← Check sequence number, send ACK/NACK
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Hamming Decode  │  ← Compute syndrome → detect/correct error
└────────┬─────────┘
         │
    Delivered Data
```

---

### Component Overview

#### `data_link_layer.cpp`

| Component | Class/Function | Description |
|---|---|---|
| Hamming Encoder | `hammingEncode()` | Encodes m-bit data with parity bits at power-of-2 positions |
| Hamming Decoder | `hammingDecode()` | Computes syndrome, corrects bit if error detected |
| Go-Back-N Sender | `GBNSender` | Manages sliding window, sequence numbers, timeouts |
| Go-Back-N Receiver | `GBNReceiver` | Buffers in-order frames, sends cumulative ACKs |
| CSMA/CA Node | `CSMACANode` | Carrier sense, RTS/CTS, binary exponential backoff |
| Channel | `Channel` | Shared medium, handles NAV, packet loss injection |
| Simulation | `main()` | Orchestrates Node A, B, C; injects errors/loss |

#### `pyshark_analyzer.py`

| Component | Description |
|---|---|
| Live Capture | Captures loopback/UDP traffic generated by the C++ simulation |
| Frame Parser | Extracts frame type, sequence number, ACK/NACK, window state |
| Statistics | Frame loss rate, retransmission count, throughput, window utilization |
| Color Output | `colorama`-powered terminal display (green=ACK, red=NACK/lost) |
| Table Report | `tabulate`-formatted summary table per session |

---

### How to Compile and Run

#### Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| g++ / MinGW | ≥ C++17 | Compile the simulation |
| Python | ≥ 3.8 | Run the PyShark analyzer |
| Wireshark / Npcap | Latest | Required by PyShark for packet capture |
| pip packages | — | `pyshark`, `colorama`, `tabulate` |

#### Step 1 — Compile the C++ Simulation

```bash
# Linux / macOS
g++ -std=c++17 data_link_layer.cpp -o data_link_layer

# Windows (MinGW / MSYS2)
g++ -std=c++17 data_link_layer.cpp -o data_link_layer.exe
```

#### Step 1 — Compile the Modular C++ Simulation

You can compile using `build.bat` on Windows or via `g++`:

```bash
# Option A: 1-Click Build (Windows)
.\build.bat

# Option B: Manual g++ Command
g++ -std=c++14 -Wall -Wextra main.cpp utils.cpp hamming.cpp csma_ca.cpp go_back_n.cpp -o data_link_layer.exe
```

#### Step 2 — Run the C++ Simulation

```bash
# Windows
.\data_link_layer.exe
```

#### Step 3 — Run the PyShark Analyzer

```bash
python pyshark_analyzer.py
```

> **Tip:** You can inspect the packets in two ways:
> 1. Run `python pyshark_analyzer.py` to get the automated dissection, window state tracing, and error analysis via PyShark.
> 2. Open `packet_capture.pcap` directly in **Wireshark GUI** to explore the Ethernet, IP, UDP, and custom Data Link frames visually!
> 3. For live capture, run `python pyshark_analyzer.py --live` concurrently in a separate terminal.

#### Step 4 — View or Re-generate the Colorful PowerPoint Presentation

A 10-slide widescreen (16:9) presentation has been generated:
- File: `data_link_layer_presentation.pptx`
- Generator script: `python create_presentation.py`

#### Directory Structure

```
END PROJECT/
├── common.h                     ← Shared structures (Frame, Node, Channel), constants & test vectors
├── utils.h / utils.cpp          ← Timestamps, console banner formatting, JSON logger & PCAP generator
├── hamming.h / hamming.cpp      ← Error Control: (12,8) encoding, syndrome decoding, bit-error correction
├── csma_ca.h / csma_ca.cpp      ← Multiple Access: DIFS, SIFS, RTS/CTS handshakes & exponential backoff
├── go_back_n.h / go_back_n.cpp  ← Flow Control: sliding window (W=4), cumulative ACKs & rollback
├── main.cpp                     ← Clean main entry point orchestrating all modules (< 80 lines)
├── build.bat                    ← 1-click compilation script
├── data_link_layer.exe          ← Compiled Windows binary
├── packet_capture.pcap          ← Real PCAP capture file (dissected by PyShark / Wireshark)
├── packet_log.txt               ← Structured JSON line log of every packet movement
├── pyshark_analyzer.py          ← PyShark packet analyzer & visualizer (monochrome / clean)
├── create_presentation.py       ← Python generator for the presentation
├── data_link_layer_presentation.pptx ← 10-slide colorful presentation on architecture, theory & results
└── README.md                    ← Comprehensive documentation & dry run
```

---

## 2. Concepts Used & Surrounding Theory

### Data Link Layer Overview

The **Data Link Layer** is Layer 2 of the OSI (Open Systems Interconnection) model. It sits between the Physical Layer (Layer 1) and the Network Layer (Layer 3).

```
┌───────────────────────────────┐
│  7. Application Layer         │
├───────────────────────────────┤
│  6. Presentation Layer        │
├───────────────────────────────┤
│  5. Session Layer             │
├───────────────────────────────┤
│  4. Transport Layer           │
├───────────────────────────────┤
│  3. Network Layer             │  ← IP addresses, routing
├───────────────────────────────┤
│  2. DATA LINK LAYER  ◄────────┼── THIS PROJECT
│     • Framing                 │
│     • MAC (CSMA/CA)           │
│     • Error Control (Hamming) │
│     • Flow Control (GBN ARQ)  │
├───────────────────────────────┤
│  1. Physical Layer            │  ← Bits on the wire/air
└───────────────────────────────┘
```

#### Responsibilities of the Data Link Layer

| Responsibility | Mechanism | Description |
|---|---|---|
| **Framing** | Headers + Trailers | Delimits packets into frames for transmission |
| **Physical Addressing** | MAC addresses | Identifies source and destination on the LAN |
| **Error Control** | Hamming, CRC, Parity | Detects and corrects transmission errors |
| **Flow Control** | Sliding Window (GBN) | Prevents a fast sender from overwhelming a slow receiver |
| **Access Control** | CSMA/CA | Arbitrates access to a shared medium |

---

### Framing

Framing is the process of breaking a raw bit stream from the Physical Layer into discrete, bounded units called **frames**. This gives structure to the data so the receiver knows where one frame ends and another begins.

#### Frame Structure

```
┌──────────┬──────────┬────────────────┬──────────┬──────────────┐
│ Preamble │  Header  │    Payload     │  Trailer │  Frame Delim │
│ (sync)   │ src/dst  │  (data field)  │  (CRC)   │  (flag byte) │
│ 10101010 │ MAC addr │  Up to MTU     │ checksum │   01111110   │
└──────────┴──────────┴────────────────┴──────────┴──────────────┘
```

#### Framing Techniques

**1. Bit Stuffing** (used in HDLC)
- A special flag `01111110` marks frame boundaries.
- Sender inserts a `0` after every five consecutive `1`s in data.
- Receiver removes any `0` that follows five `1`s.

```
Data:     011111 10001
Stuffed:  0111110 10001   ← '0' inserted after five 1s
```

**2. Byte Stuffing** (used in PPP)
- A special `FLAG` byte (e.g., `0x7E`) marks boundaries.
- If `FLAG` appears in data, it is preceded by an `ESC` byte (`0x7D`).
- If `ESC` appears in data, it is doubled.

**3. Length Field**
- A fixed-size length field in the header declares how many bytes the frame contains.
- Simple and efficient; used in Ethernet (IEEE 802.3).

---

### Error Control — Hamming Code

Errors in transmission are caused by noise, interference, or hardware faults. The Data Link Layer is responsible for detecting (and optionally correcting) these errors before passing frames upward.

#### Types of Errors

| Type | Description | Example |
|---|---|---|
| Single-bit error | Exactly one bit flips | `1011` → `1001` |
| Burst error | Consecutive bits corrupted | `1011010` → `1000110` |

#### Parity Bits

- **Even Parity**: Total number of `1`s (data + parity) must be even.
- **Odd Parity**: Total number of `1`s must be odd.

A single parity bit can **detect** a single-bit error but cannot **correct** it (we don't know *which* bit flipped).

#### Hamming Code — Single Error Correction (SEC)

Hamming code adds redundant **parity bits** at positions that are powers of 2: positions `1, 2, 4, 8, 16, ...`

**Number of parity bits needed:**

For `m` data bits, the number of parity bits `r` satisfies:

$$2^r \geq m + r + 1$$

| Data bits (m) | Parity bits (r) | Total bits |
|---|---|---|
| 1 | 2 | 3 |
| 2–4 | 3 | 5–7 |
| 5–11 | 4 | 9–15 |
| 12–26 | 5 | 17–31 |

#### Step-by-Step Example: Encode Data `1011`

**Data bits:** `m = 4` → need `r = 3` parity bits → total `n = 7` bits

**Step 1 — Place data bits at non-power-of-2 positions:**

| Position | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
|---|---|---|---|---|---|---|---|
| Role | D | D | D | P | D | P | P |
| Value | 1 | 0 | 1 | ? | 1 | ? | ? |

Data bits go to positions 3, 5, 6, 7 (non-powers of 2): `D3=1, D5=1, D6=0, D7=1`

**Step 2 — Calculate each parity bit (even parity):**

**P1 (position 1):** covers positions where bit 0 of index = 1 → positions `1, 3, 5, 7`
```
P1 covers: pos 1(P1), pos 3(D=1), pos 5(D=1), pos 7(D=1)
P1 XOR 1 XOR 1 XOR 1 = 1   →  P1 = 1
```

**P2 (position 2):** covers positions where bit 1 of index = 1 → positions `2, 3, 6, 7`
```
P2 covers: pos 2(P2), pos 3(D=1), pos 6(D=0), pos 7(D=1)
P2 XOR 1 XOR 0 XOR 1 = 0   →  P2 = 0
```

**P4 (position 4):** covers positions where bit 2 of index = 1 → positions `4, 5, 6, 7`
```
P4 covers: pos 4(P4), pos 5(D=1), pos 6(D=0), pos 7(D=1)
P4 XOR 1 XOR 0 XOR 1 = 0   →  P4 = 0
```

**Step 3 — Final encoded word:**

| Position | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
|---|---|---|---|---|---|---|---|
| Value | **1** | **0** | **1** | **0** | **1** | **0** | **1** |

**Encoded frame: `1010101`** (reading left to right: positions 7→1)

#### Syndrome Decoding — Detecting and Correcting Errors

Suppose the received word is `1010111` (bit at position 1 flipped from 1→1... let's say position 3 was flipped):

Received: `1 0 1 0 1 1 1` → position 3 has value `1` flipped to `0` → received `1010011`

**Compute syndrome:**

```
S1 = P1 ⊕ D3 ⊕ D5 ⊕ D7  =  1 ⊕ 0 ⊕ 1 ⊕ 1  =  1  ← error in P1's group
S2 = P2 ⊕ D3 ⊕ D6 ⊕ D7  =  0 ⊕ 0 ⊕ 0 ⊕ 1  =  1  ← error in P2's group
S4 = P4 ⊕ D5 ⊕ D6 ⊕ D7  =  0 ⊕ 1 ⊕ 0 ⊕ 1  =  0  ← no error in P4's group

Syndrome = S4 S2 S1 = 0 1 1 = 3 (decimal)
```

**Error is at position 3** → flip bit 3 → corrected.

> If syndrome = `000` → no error detected.
> Syndrome value directly gives the error position.

---

### Flow Control — Go-Back-N ARQ

**Flow control** prevents the sender from transmitting data faster than the receiver can process it. Without it, the receiver's buffer overflows and frames are silently dropped.

#### Why Flow Control is Needed

```
  Sender (Fast CPU)          Receiver (Slow CPU)
  ──────────────────         ─────────────────────
  Sends 1000 frames/s   →   Can only process 100 frames/s
                             Buffer fills up → frames DROPPED
```

#### Sliding Window Protocol

Instead of waiting for an ACK after every frame (Stop-and-Wait), the sender can have multiple frames "in flight" simultaneously. The **window** is the set of frames that have been sent but not yet acknowledged.

```
Sequence Numbers:  0  1  2  3  4  5  6  7  0  1  2 ...
                   ├──────────────┤
                   │   Window=4   │
                   │ ■  ■  □  □  │
                   │ sent  unsent │
                   └──────────────┘
                   ▲              ▲
                SBase          SBase+W-1
```

#### Go-Back-N ARQ Rules

| Event | Sender Action | Receiver Action |
|---|---|---|
| New frame to send | Send if within window | — |
| ACK(n) received | Advance window base to n+1 | — |
| NAK(n) received | Retransmit frame n and ALL subsequent | — |
| Timeout | Retransmit ALL unacknowledged frames | — |
| Frame received in order | — | Accept, deliver, send ACK(n) |
| Frame received out of order | — | **Discard**, send ACK for last in-order frame |

#### Sequence Number Space

The sequence number space must be **strictly greater** than the window size:

$$\text{Sequence Space} > W \quad \text{(for Go-Back-N)}$$

If window size W = 4, we need at least 5 sequence numbers (0–4), but conventionally use powers of 2, so 3-bit sequence numbers give space of 8.

> **Why?** If the sender uses a window of W = 2^n and uses 2^n sequence numbers, the receiver cannot distinguish between a new frame and a retransmission of the same sequence number.

#### Efficiency Formula

$$\eta = \begin{cases} \dfrac{W}{1 + 2a} & \text{if } W < 1 + 2a \\[10pt] 1 & \text{if } W \geq 1 + 2a \end{cases}$$

Where:
- $W$ = window size (number of frames in flight)
- $a = \dfrac{T_p}{T_t}$ = propagation delay / transmission time
- $T_p$ = one-way propagation delay
- $T_t$ = frame transmission time

**Example:** W=4, Tp=10ms, Tt=5ms → a = 2 → η = 4/(1+4) = **0.8 (80%)**

#### Protocol Comparison

| Feature | Stop-and-Wait | Go-Back-N | Selective Repeat |
|---|---|---|---|
| Window Size | 1 | W (any) | W ≤ 2^(n-1) |
| Receiver Buffer | 1 frame | 1 frame | W frames |
| On Error | Retransmit 1 | Retransmit W frames | Retransmit 1 frame |
| Complexity | Low | Medium | High |
| Efficiency | Low (a>>1) | Medium-High | Highest |
| Seq Num Space | 2 | > W | ≥ 2W |

#### Go-Back-N State Diagram

```
           ┌─────────────────────────────────────┐
           │           SENDER STATES              │
           │                                      │
           │   ┌──────────┐     send frame        │
           │   │  IDLE    │──────────────────────▶│
           │   └──────────┘                        │
           │         ▲                ┌──────────┐ │
           │    all ACK'd             │WINDOW    │ │
           │         └────────────────│OPEN      │ │
           │                         │(transmit) │ │
           │                         └──────────┘ │
           │                              │        │
           │              timeout / NAK   │        │
           │                         ┌───▼──────┐ │
           │                         │RETRANSMIT│ │
           │                         │(go back) │ │
           │                         └──────────┘ │
           └─────────────────────────────────────┘
```

---

### Multiple Access — CSMA/CA

**CSMA/CA** (Carrier Sense Multiple Access / **Collision Avoidance**) is the MAC protocol used in IEEE 802.11 (Wi-Fi) wireless networks.

#### Why CSMA/CA instead of CSMA/CD?

**CSMA/CD** (Collision *Detection*) works on wired Ethernet because a node can simultaneously transmit and monitor the medium for collisions. On a wireless medium:

1. **A transmitting node's own signal drowns out any incoming signal** — it cannot hear collisions while transmitting (near-far problem).
2. **Hidden Node Problem**: Node A and Node C are both in range of Node B, but out of range of each other. They cannot detect each other's transmissions → they collide at B without knowing.

```
Hidden Node Problem:
     ┌──── range ────┐   ┌──── range ────┐
     │               │   │               │
   [Node A] ~~~~ [Node B] ~~~~ [Node C]
     │                               │
     └─ A cannot hear C ─────────────┘
        C cannot hear A
```

3. **Exposed Node Problem**: Node B is transmitting to Node A. Node C wants to transmit to Node D (outside B's range), but C senses the medium as busy and unnecessarily defers.

#### CSMA/CA Operation (IEEE 802.11 DCF)

**Key Time Intervals:**

| Interval | Duration | Purpose |
|---|---|---|
| DIFS | ~50 µs | DCF Inter-Frame Space — mandatory idle wait before transmission |
| SIFS | ~10 µs | Short IFS — used for ACK/CTS frames (highest priority) |
| Slot Time | ~20 µs | Minimum backoff unit |
| AIFS | Variable | Arbitration IFS (QoS extension) |

#### RTS/CTS Handshake

Before sending a large data frame, the sender performs a virtual channel reservation:

```
Node A          Node B          Node C (hidden)
  │                │                │
  │──── RTS ──────▶│                │
  │  (Reserve for  │                │
  │   duration X)  │                │
  │                │──── CTS ──────▶│  (Node C hears CTS)
  │◀─── CTS ───────│                │
  │                │                │ NAV = X
  │                │                │ (Node C defers)
  │──── DATA ─────▶│                │
  │◀─── ACK ───────│                │
  │                │                │ NAV expires
  │                │                │ (Node C can now transmit)
```

**RTS Frame Fields:**

| Field | Size | Content |
|---|---|---|
| Frame Control | 2 bytes | Type = RTS |
| Duration (NAV) | 2 bytes | Time needed for DATA + ACK + 2×SIFS |
| Receiver Address | 6 bytes | Destination MAC |
| Transmitter Address | 6 bytes | Source MAC |
| FCS | 4 bytes | Frame check sequence |

**CTS Frame Fields:**

| Field | Size | Content |
|---|---|---|
| Frame Control | 2 bytes | Type = CTS |
| Duration (NAV) | 2 bytes | RTS.NAV − SIFS |
| Receiver Address | 6 bytes | Copied from RTS.TA |
| FCS | 4 bytes | Frame check sequence |

**NAV (Network Allocation Vector):** A virtual timer maintained by each node. A node that hears a CTS sets its NAV countdown and considers the channel busy until NAV expires, even if it cannot sense any signal.

#### Binary Exponential Backoff

When a node wants to transmit but finds the channel busy, it:

1. Waits for the channel to become IDLE.
2. Waits an additional **DIFS** period.
3. Chooses a random backoff counter **k** from `[0, CW − 1]`:

$$k \in [0,\ CW_{\min} \cdot 2^i - 1]$$

where `i` is the collision/backoff attempt number (starts at 0).

4. Decrements k by 1 each idle slot. Freezes k if the channel becomes busy again.
5. Transmits when k = 0.

**Contention Window Growth:**

| Attempt | CWmin | CWmax | Window Range |
|---|---|---|---|
| 0 (first try) | 15 | — | [0, 15] |
| 1 | 31 | — | [0, 31] |
| 2 | 63 | — | [0, 63] |
| 3 | 127 | — | [0, 127] |
| 4 | 255 | — | [0, 255] |
| 5+ | 255 | 1023 | [0, 1023] (capped) |

This **exponential growth** reduces the probability of simultaneous retransmission after a collision.

#### Full CSMA/CA Flowchart

```
     Node wants to transmit
              │
              ▼
     ┌────────────────┐
     │ Sense channel  │
     └────────┬───────┘
              │
     ┌────────▼───────┐   BUSY   ┌─────────────────┐
     │ Channel IDLE?  │─────────▶│ Wait (freeze     │
     └────────┬───────┘          │ backoff counter) │
              │ IDLE             └─────────┬────────┘
              ▼                            │ IDLE
     ┌────────────────┐◀──────────────────┘
     │  Wait DIFS     │
     └────────┬───────┘
              │
              ▼
     ┌────────────────┐
     │ Random backoff │
     │  k ∈ [0, CW-1]│
     └────────┬───────┘
              │
     ┌────────▼───────┐
     │   k == 0 ?     │───No──▶ (Decrement k; check channel)
     └────────┬───────┘
              │ Yes
              ▼
     ┌────────────────┐
     │   Send RTS     │
     └────────┬───────┘
              │
     ┌────────▼───────┐   Timeout  ┌──────────────────┐
     │  CTS received? │───────────▶│ Backoff (double  │
     └────────┬───────┘            │ CW, retry)       │
              │ Yes                └──────────────────┘
              ▼
     ┌────────────────┐
     │  Send DATA     │
     └────────┬───────┘
              │
     ┌────────▼───────┐   Timeout  ┌──────────────────┐
     │  ACK received? │───────────▶│ Retransmit (GBN) │
     └────────┬───────┘            └──────────────────┘
              │ Yes
              ▼
        Transmission Complete
```

---

## 3. Example Dry Run

### Scenario Setup

| Parameter | Value |
|---|---|
| Nodes | Node A (sender), Node B (receiver), Node C (contender) |
| Node A frames | 6 frames (seq 0–5), data: `["HELLO", "WORLD", "DATA1", "DATA2", "DATA3", "END!!"]` |
| Node C frames | 2 frames (seq 0–1) |
| Window Size (W) | 4 (sequence numbers 0–7) |
| Injected error | Frame 3 (seq=2) has a single-bit flip → Hamming corrects |
| Injected loss | Frame 4 (seq=3) lost in transit → Go-Back-N retransmits from seq=3 |
| Error control | Hamming(7,4) — 4 data bits, 3 parity bits, 7-bit codeword |

### Notation

```
■ = frame sent & acknowledged
▣ = frame sent, awaiting ACK
□ = frame not yet sent
✗ = frame lost / errored
✔ = frame received and accepted
```

---

### Phase 1 — CSMA/CA Channel Access (Node A and Node C contend)

**t = 0.00ms** — Both Node A and Node C have frames to send.

```
Channel State:  IDLE
Node A:         Senses channel → IDLE
Node C:         Senses channel → IDLE
```

**t = 0.10ms** — Both nodes wait DIFS (50µs). Both choose backoff counters.

```
Node A:  Backoff k_A = rand[0,15] = 3   (3 slots = 3×20µs = 60µs)
Node C:  Backoff k_C = rand[0,15] = 7   (7 slots = 7×20µs = 140µs)
```

**t = 0.16ms** — Node A's counter reaches 0 first.

```
Node A:  k_A = 0 → TRANSMIT RTS
Node C:  k_C = 4 (countdown frozen — channel busy)
```

**t = 0.16ms** — **Node A sends RTS to Node B**

```
RTS Frame:
  ┌──────────────┬────────────┬──────────────────┐
  │ Type = RTS   │ NAV = 5ms  │ From=A, To=B     │
  └──────────────┴────────────┴──────────────────┘
```

**t = 0.17ms** — **Node B receives RTS, sends CTS**

```
CTS Frame:
  ┌──────────────┬────────────────┬────────────────┐
  │ Type = CTS   │ NAV = 4.9ms    │ To=A           │
  └──────────────┴────────────────┴────────────────┘
```

**t = 0.17ms** — **Node C hears CTS → sets NAV = 4.9ms → DEFERS**

```
[CSMA/CA] Node C: CTS overheard. NAV set to 4.9ms. Deferring.
Channel:    BUSY (virtual, via NAV)
Node A:     CTS received. ✔ Channel reserved. Begin data transmission.
```

---

### Phase 2 — Go-Back-N Normal Transmission (Frames 0, 1)

**Window initial state:**
```
Seq:    [ 0 ][ 1 ][ 2 ][ 3 ][ 4 ][ 5 ][ 6 ][ 7 ]
Window: [□  ][□  ][□  ][□  ]
         ▲
        SBase=0    (Window = [0,1,2,3])
```

---

#### Frame 0 — "HELLO"

**t = 0.20ms** — Node A transmits Frame 0.

**Hamming Encoding of "H" (01001000 → take 4 bits: `0100`):**

| Position | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
|---|---|---|---|---|---|---|---|
| Role | D7 | D6 | D5 | P4 | D3 | P2 | P1 |
| Data | 0 | 1 | 0 | ? | 0 | ? | ? |

```
P1 (pos 1,3,5,7): 0 XOR 0 XOR 0 XOR 0 = 0  →  P1=0
P2 (pos 2,3,6,7): 0 XOR 0 XOR 1 XOR 0 = 1  →  P2=1
P4 (pos 4,5,6,7): 0 XOR 0 XOR 1 XOR 0 = 1  →  P4=1
Encoded frame 0:  0 1 0 1 0 1 0  (positions 7→1)
```

```
[t=0.20ms] [CSMA/CA] Channel: BUSY (data transmission)
[t=0.20ms] [GBN]     Node A → Frame 0 | seq=0 | data=0100 | encoded=0101010
[t=0.20ms] [GBN]     Window: [▣][□][□][□]
                               0  1  2  3
```

**t = 0.25ms** — Node B receives Frame 0. Hamming decode: syndrome = `000` → No error.

```
[t=0.25ms] [HAMMING] Frame 0: Syndrome=000 → No error ✔
[t=0.25ms] [GBN]     Node B: Frame 0 accepted. Send ACK(0).
[t=0.30ms] [GBN]     Node A: ACK(0) received. Advance window.
```

**Window after ACK(0):**
```
Seq:    [ 0 ][ 1 ][ 2 ][ 3 ][ 4 ][ 5 ][ 6 ][ 7 ]
Window:      [□  ][□  ][□  ][□  ]
              ▲
             SBase=1    (Window = [1,2,3,4])
Status: ■ □ □ □ □ □ □ □
        0 1 2 3 4 5 6 7
```

---

#### Frame 1 — "WORLD"

**t = 0.31ms** — Node A transmits Frame 1.

```
[t=0.31ms] [HAMMING] Encoding 'W' (0111) → P1=1, P2=0, P4=1 → Encoded: 0111011
[t=0.31ms] [GBN]     Node A → Frame 1 | seq=1 | encoded=0111011
[t=0.31ms] [GBN]     Window: [■][▣][□][□]
                               0  1  2  3  (relative to SBase=0)
```

**t = 0.36ms** — Node B receives Frame 1. No error.

```
[t=0.36ms] [HAMMING] Frame 1: Syndrome=000 → No error ✔
[t=0.36ms] [GBN]     Node B: Frame 1 accepted. Send ACK(1).
[t=0.40ms] [GBN]     Node A: ACK(1) received. Advance window.
```

**Window after ACK(1):**
```
Status: ■  ■  □  □  □  □  □  □
        0  1  2  3  4  5  6  7
Window:       [□ ][□ ][□ ][□ ]
               ▲
              SBase=2
```

---

### Phase 3 — Error Injection & Hamming Correction (Frame 2)

#### Frame 2 — "DATA1" (with injected single-bit error)

**t = 0.41ms** — Node A transmits Frame 2.

```
[t=0.41ms] [HAMMING] Encoding 'D' (1000) → P1=1, P2=0, P4=1 → Encoded: 1000101
[t=0.41ms] [GBN]     Node A → Frame 2 | seq=2 | encoded=1000101
[t=0.41ms] [GBN]     Window: [■][■][▣][□]
                               0  1  2  3
```

**t = 0.44ms** — **Noise on channel flips bit at position 5!**

```
[CHANNEL]  ⚡ BIT ERROR INJECTED at position 5 of Frame 2!
           Sent:     1 0 0 0 1 0 1
           Received: 1 0 0 0 0 0 1
                              ▲
                         bit 5 flipped: 1→0
```

**t = 0.46ms** — Node B receives corrupted Frame 2. Hamming decoder runs:

```
Received codeword (pos 7→1): 1 0 0 0 0 0 1

S1 (pos 1,3,5,7): P1 ⊕ D3 ⊕ D5 ⊕ D7 = 1 ⊕ 0 ⊕ 0 ⊕ 1 = 0
S2 (pos 2,3,6,7): P2 ⊕ D3 ⊕ D6 ⊕ D7 = 0 ⊕ 0 ⊕ 0 ⊕ 1 = 1
S4 (pos 4,5,6,7): P4 ⊕ D5 ⊕ D6 ⊕ D7 = 1 ⊕ 0 ⊕ 0 ⊕ 1 = 0   ← wait

Let's recheck with correct values:
Sent:     pos7=1 pos6=0 pos5=0 pos4=0 pos3=0 pos2=0 pos1=1
                                     *** *** *** *** ***
Actually encoding 1000 (D=4 bits at positions 3,5,6,7):
  D7=1, D6=0, D5=0, D3=0
  P1 (1,3,5,7) = 0⊕0⊕0⊕1 = 1  →  P1=1 ✔ (pos1=1)
  P2 (2,3,6,7) = 0⊕0⊕0⊕1 = 1  →  P2=1 (pos2=1) ← wait recompute
  P4 (4,5,6,7) = 0⊕0⊕0⊕1 = 1  →  P4=1 (pos4=1)

Correct encoded:  1 0 0 1 0 1 1   (pos 7→1)
Received (err5):  1 0 0 1 1 1 1   ← pos5 flipped 0→1

Syndrome:
  S1(1,3,5,7): P1⊕D3⊕D5⊕D7 = 1⊕0⊕1⊕1 = 1
  S2(2,3,6,7): P2⊕D3⊕D6⊕D7 = 1⊕0⊕0⊕1 = 0
  S4(4,5,6,7): P4⊕D5⊕D6⊕D7 = 1⊕1⊕0⊕1 = 1
  Syndrome = S4 S2 S1 = 1 0 1 = 5 (decimal)

ERROR at position 5 → flip bit 5 → CORRECTED!
```

```
[t=0.46ms] [HAMMING] Frame 2: Syndrome=101 → Error at bit position 5!
[t=0.46ms] [HAMMING] Correcting bit 5: 1→0
[t=0.46ms] [HAMMING] Frame 2 CORRECTED ✔ (data recovered: 1000)
[t=0.46ms] [GBN]     Node B: Frame 2 accepted. Send ACK(2).
[t=0.50ms] [GBN]     Node A: ACK(2) received. Advance window.
```

**Window after ACK(2):**
```
Status: ■  ■  ■  □  □  □  □  □
        0  1  2  3  4  5  6  7
Window:          [□ ][□ ][□ ][□ ]
                  ▲
                 SBase=3
```

---

### Phase 4 — Frame Loss & Go-Back-N Rollback (Frame 3)

#### Frame 3 — "DATA2" (injected packet loss)

**t = 0.51ms** — Node A transmits Frames 3 and 4 (window allows it).

```
[t=0.51ms] [GBN]     Node A → Frame 3 | seq=3 (DATA2)
[t=0.53ms] [GBN]     Node A → Frame 4 | seq=4 (DATA3)
[t=0.55ms] [GBN]     Node A → Frame 5 | seq=5 (END!!)
[t=0.51ms] [GBN]     Window: [■][■][■][▣][▣][▣][ ][ ]
                               0  1  2  3  4  5
```

**t = 0.54ms** — **Frame 3 is lost in transit (simulated channel drop)!**

```
[CHANNEL]  ✗ PACKET LOSS: Frame 3 (seq=3) DROPPED
           (Simulating congestion / physical layer failure)
```

**t = 0.58ms** — Node B receives Frame 4 (seq=4). But seq=4 ≠ expected seq=3.

```
[t=0.58ms] [GBN]     Node B: Received seq=4, expected seq=3.
[t=0.58ms] [GBN]     Node B: OUT OF ORDER → DISCARD seq=4.
[t=0.58ms] [GBN]     Node B: Sends NACK(3) (or repeat ACK(2)).
```

**t = 0.60ms** — Node B receives Frame 5 (seq=5). Still wrong.

```
[t=0.60ms] [GBN]     Node B: Received seq=5, expected seq=3.
[t=0.60ms] [GBN]     Node B: OUT OF ORDER → DISCARD seq=5.
[t=0.60ms] [GBN]     Node B: Sends NACK(3).
```

**t = 0.80ms** — **TIMEOUT for Frame 3 expires at Node A!**

```
[t=0.80ms] [GBN]     ⏰ TIMEOUT! Frame 3 (seq=3) unacknowledged.
[t=0.80ms] [GBN]     Go-Back-N: Rolling back to seq=3.
[t=0.80ms] [GBN]     Retransmitting: Frame 3, Frame 4, Frame 5
```

**Window during rollback:**
```
Before rollback:
  Status: ■  ■  ■  ▣  ▣  ▣  □  □
          0  1  2  3  4  5  6  7
           sent, lost ─▲─ sent, discarded

After rollback (GBN):
  Window pointer reset to SBase=3
  Status: ■  ■  ■  □  □  □  □  □
          0  1  2  3  4  5  6  7
                    ▲
               Restart from here
```

#### Retransmission of Frames 3, 4, 5

**t = 0.82ms** — Node A retransmits Frame 3.

```
[t=0.82ms] [HAMMING] Encoding 'D' (1000) → Encoded: 1001011
[t=0.82ms] [GBN]     Node A → RETRANSMIT Frame 3 | seq=3
[t=0.87ms] [HAMMING] Frame 3: Syndrome=000 → No error ✔
[t=0.87ms] [GBN]     Node B: Frame 3 accepted (seq=3=expected). ACK(3).
[t=0.90ms] [GBN]     Node A: ACK(3) received. Advance window.
```

**t = 0.91ms** — Node A retransmits Frame 4.

```
[t=0.91ms] [GBN]     Node A → RETRANSMIT Frame 4 | seq=4
[t=0.96ms] [GBN]     Node B: Frame 4 accepted. ACK(4).
[t=0.99ms] [GBN]     Node A: ACK(4) received.
```

**t = 1.00ms** — Node A retransmits Frame 5.

```
[t=1.00ms] [GBN]     Node A → RETRANSMIT Frame 5 | seq=5
[t=1.05ms] [GBN]     Node B: Frame 5 accepted. ACK(5).
[t=1.08ms] [GBN]     Node A: ACK(5) received. ALL FRAMES DELIVERED ✔
```

**Final window state for Node A:**
```
Status: ■  ■  ■  ■  ■  ■  □  □
        0  1  2  3  4  5  6  7
All 6 frames sent and acknowledged. Window fully closed.
```

**Node A's transmission complete!**

```
[t=1.08ms] [CSMA/CA] Node A releases channel.
[t=1.08ms] [CSMA/CA] Channel: IDLE
```

---

### Phase 5 — Node C's Turn

**t = 1.09ms** — Node C's NAV timer has long expired. Node C senses channel: IDLE.

```
[t=1.09ms] [CSMA/CA] Node C: Channel IDLE. Wait DIFS.
[t=1.14ms] [CSMA/CA] Node C: Backoff k_C = 4 slots remaining (resumed from before).
[t=1.22ms] [CSMA/CA] Node C: k_C = 0. Sending RTS.
```

**t = 1.22ms** — Node C sends RTS to Node B.

```
[t=1.22ms] [CSMA/CA] Node C → RTS → Node B (NAV=2ms)
[t=1.23ms] [CSMA/CA] Node B → CTS → Node C
[t=1.23ms] [CSMA/CA] Channel reserved for Node C.
```

**t = 1.24ms** — Node C transmits 2 frames (no errors, no loss).

```
[t=1.24ms] [GBN]     Node C → Frame 0 | seq=0 → ACK(0) ✔
[t=1.34ms] [GBN]     Node C → Frame 1 | seq=1 → ACK(1) ✔
[t=1.44ms] [CSMA/CA] Node C: All frames delivered. Channel released.
```

---

### Complete Execution Summary Table

| Time (ms) | Event | Node | Frame/Seq | Result |
|---|---|---|---|---|
| 0.00 | Channel sensing | A, C | — | Both sense IDLE |
| 0.10 | Backoff | A | k=3 | A wins backoff |
| 0.10 | Backoff | C | k=7 | C defers |
| 0.16 | RTS sent | A | — | RTS → Node B |
| 0.17 | CTS received | A | — | Channel reserved |
| 0.17 | NAV set | C | — | C defers 4.9ms |
| 0.20 | Frame sent | A | seq=0 | Encoded, transmitted |
| 0.30 | ACK | B→A | seq=0 | Accepted ✔ |
| 0.31 | Frame sent | A | seq=1 | Encoded, transmitted |
| 0.40 | ACK | B→A | seq=1 | Accepted ✔ |
| 0.41 | Frame sent | A | seq=2 | Bit error injected |
| 0.46 | Error corrected | B | seq=2 | Syndrome=5, bit 5 fixed |
| 0.50 | ACK | B→A | seq=2 | Accepted ✔ |
| 0.51 | Frame sent | A | seq=3 | **LOST in channel** ✗ |
| 0.53 | Frame sent | A | seq=4 | Discarded by B (OOO) |
| 0.55 | Frame sent | A | seq=5 | Discarded by B (OOO) |
| 0.80 | **TIMEOUT** | A | seq=3 | GBN rollback → resend 3,4,5 |
| 0.82 | RETRANSMIT | A | seq=3 | No error |
| 0.87 | ACK | B→A | seq=3 | Accepted ✔ |
| 0.91 | RETRANSMIT | A | seq=4 | No error |
| 0.96 | ACK | B→A | seq=4 | Accepted ✔ |
| 1.00 | RETRANSMIT | A | seq=5 | No error |
| 1.05 | ACK | B→A | seq=5 | Accepted ✔ |
| 1.08 | Channel released | A | — | All 6 frames delivered |
| 1.09 | Channel sensing | C | — | IDLE, resume backoff |
| 1.22 | RTS sent | C | — | RTS → Node B |
| 1.24 | Frame sent | C | seq=0 | Accepted ✔ |
| 1.34 | Frame sent | C | seq=1 | Accepted ✔ |
| 1.44 | Simulation complete | — | — | All frames delivered ✔ |

---

### Sliding Window Visualization (Node A)

```
Step 1 — Initial (before any transmission):
  [ □ ][ □ ][ □ ][ □ ]  □  □  □  □
    0    1    2    3     4  5  6  7
    ▲─── Window ───▲

Step 2 — Frame 0 sent:
  [ ▣ ][ □ ][ □ ][ □ ]  □  □  □  □
    0    1    2    3

Step 3 — ACK(0) received:
  ■  [ □ ][ □ ][ □ ][ □ ]  □  □  □
  0    1    2    3    4

Step 4 — Frame 1 sent, ACK(1) received:
  ■    ■  [ □ ][ □ ][ □ ][ □ ]  □  □
  0    1    2    3    4    5

Step 5 — Frame 2 sent (error!), corrected, ACK(2):
  ■    ■    ■  [ □ ][ □ ][ □ ][ □ ]  □
  0    1    2    3    4    5    6

Step 6 — Frames 3,4,5 sent; Frame 3 LOST:
  ■    ■    ■  [ ▣ ][ ▣ ][ ▣ ][ □ ]  □
  0    1    2    3✗   4↓   5↓   6
                  ↑ lost  ↑ discarded (OOO)

Step 7 — TIMEOUT → GBN rollback:
  ■    ■    ■  [ □ ][ □ ][ □ ][ □ ]  □
  0    1    2    3    4    5    6
               ← window reset to SBase=3

Step 8 — Retransmit 3,4,5; All ACKed:
  ■    ■    ■    ■    ■    ■  [ □ ][ □ ]
  0    1    2    3    4    5    6    7
                              ▲
                          window empty, all delivered ✔
```

---

## 4. References

### Textbooks

| Topic | Resource | Chapter/Section |
|---|---|---|
| Data Link Layer Overview | Forouzan, *Data Communications and Networking*, 5th Ed. | Ch. 10 — Data Link Layer |
| Go-Back-N ARQ | Forouzan, *Data Communications and Networking*, 5th Ed. | Ch. 11 — Data Link Control |
| Hamming Code | Tanenbaum, *Computer Networks*, 5th Ed. | Ch. 3.2 — Error Detection and Correction |
| CSMA/CA & 802.11 | Tanenbaum, *Computer Networks*, 5th Ed. | Ch. 4.4 — IEEE 802.11 |
| Sliding Window | Kurose & Ross, *Computer Networking: A Top-Down Approach*, 8th Ed. | Ch. 3.4 — Principles of Reliable Data Transfer |
| Framing & Error Control | Stallings, *Data and Computer Communications*, 10th Ed. | Ch. 17 — Data Link Control |
| CSMA Protocols | Stallings, *Data and Computer Communications*, 10th Ed. | Ch. 13 — LAN Protocols |

### Online References

| Topic | Resource | Link |
|---|---|---|
| Hamming Code Tutorial | GeeksForGeeks | [https://www.geeksforgeeks.org/hamming-code-in-computer-network/](https://www.geeksforgeeks.org/hamming-code-in-computer-network/) |
| Go-Back-N Tutorial | GeeksForGeeks | [https://www.geeksforgeeks.org/sliding-window-protocol-set-2-receiver-side/](https://www.geeksforgeeks.org/sliding-window-protocol-set-2-receiver-side/) |
| Stop-and-Wait vs GBN | GeeksForGeeks | [https://www.geeksforgeeks.org/difference-between-go-back-n-protocol-and-selective-repeat-protocol/](https://www.geeksforgeeks.org/difference-between-go-back-n-protocol-and-selective-repeat-protocol/) |
| CSMA/CA Explained | Cisco Documentation | [https://www.cisco.com/c/en/us/tech/lan-switching/wireless-lan/index.html](https://www.cisco.com/c/en/us/tech/lan-switching/wireless-lan/index.html) |
| IEEE 802.11 Standard | IEEE | [https://standards.ieee.org/ieee/802.11/7028/](https://standards.ieee.org/ieee/802.11/7028/) |
| PyShark Documentation | PyShark (kiminewt) | [https://kiminewt.github.io/pyshark/](https://kiminewt.github.io/pyshark/) |
| Wireshark User Guide | Wireshark Foundation | [https://www.wireshark.org/docs/](https://www.wireshark.org/docs/) |
| Npcap (Windows capture) | Npcap | [https://npcap.com](https://npcap.com) |
| Binary Exp. Backoff | Wikipedia | [https://en.wikipedia.org/wiki/Exponential_backoff](https://en.wikipedia.org/wiki/Exponential_backoff) |
| Hidden Node Problem | Wikipedia | [https://en.wikipedia.org/wiki/Hidden_node_problem](https://en.wikipedia.org/wiki/Hidden_node_problem) |
| ARQ Protocols | Wikipedia | [https://en.wikipedia.org/wiki/Automatic_repeat_request](https://en.wikipedia.org/wiki/Automatic_repeat_request) |
| Hamming Code (original) | Bell System Technical Journal, 1950 | R.W. Hamming, "Error Detecting and Error Correcting Codes" |

### Standards

| Standard | Title | Relevance |
|---|---|---|
| IEEE 802.11-2020 | Wireless LAN Medium Access Control and Physical Layer Specifications | CSMA/CA, RTS/CTS, NAV, DIFS/SIFS |
| IEEE 802.3-2018 | Ethernet Standard | Framing, CSMA/CD (comparison) |
| ITU-T X.25 | Packet Switching | Go-Back-N ARQ origins |
| IETF RFC 793 | Transmission Control Protocol | Flow control concepts (comparison) |

---

## Appendix: Quick Formula Reference

| Formula | Description |
|---|---|
| $2^r \geq m + r + 1$ | Minimum parity bits for Hamming(m+r, m) |
| $\eta = W / (1 + 2a)$ | Go-Back-N efficiency (W < 1+2a) |
| $a = T_p / T_t$ | Propagation-to-transmission ratio |
| $\text{CW} = 2^{i+4} - 1$ | Contention window after i-th backoff |
| $\text{Seq space} > W$ | Go-Back-N sequence number requirement |
| $\text{Syndrome} = \bigoplus_{i} p_i \cdot c_i$ | Hamming syndrome (XOR of parity checks) |

---

*This project was completed as part of the Computer Networks (CN) curriculum, Semester 5. Simulation built in C++17 with PyShark-based packet analysis for live frame capture and statistics.*
