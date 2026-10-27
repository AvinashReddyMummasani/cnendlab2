#!/usr/bin/env python3
"""
create_presentation.py
Generates a modern, colorful 16:9 PowerPoint presentation for the
Data Link Layer simulation project (CSMA/CA, Go-Back-N, Hamming Codes, PyShark).
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

def create_deck():
    prs = Presentation()
    # Set 16:9 widescreen dimensions
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]  # completely blank slide

    # Color Palette
    BG_DARK       = RGBColor(15, 23, 42)      # Deep Navy #0f172a
    CARD_BG       = RGBColor(30, 41, 59)      # Slate Dark #1e293b
    CARD_BORDER   = RGBColor(51, 65, 85)      # Slate Border #334155
    CYAN          = RGBColor(6, 182, 212)     # Vibrant Cyan #06b6d4
    INDIGO        = RGBColor(99, 102, 241)    # Indigo Accent #6366f1
    GREEN         = RGBColor(16, 185, 129)    # Emerald Green #10b981
    AMBER         = RGBColor(245, 158, 11)    # Amber / Orange #f59e0b
    ROSE          = RGBColor(244, 63, 94)     # Rose Crimson #f43f5e
    PURPLE        = RGBColor(168, 85, 247)    # Purple #a855f7
    WHITE         = RGBColor(248, 250, 252)   # Off-white #f8fafc
    MUTED         = RGBColor(148, 163, 184)   # Slate text #94a3b8

    def add_bg(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_DARK
        bg.line.fill.background()
        return bg

    def add_header(slide, tag_text, title_text, tag_color=CYAN):
        # Category Tag
        tag_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.5), Inches(0.4))
        tf_tag = tag_box.text_frame
        tf_tag.word_wrap = True
        p_tag = tf_tag.paragraphs[0]
        p_tag.text = tag_text.upper()
        p_tag.font.bold = True
        p_tag.font.size = Pt(11)
        p_tag.font.color.rgb = tag_color

        # Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.5), Inches(0.7))
        tf_title = title_box.text_frame
        tf_title.word_wrap = True
        p_title = tf_title.paragraphs[0]
        p_title.text = title_text
        p_title.font.bold = True
        p_title.font.size = Pt(24)
        p_title.font.color.rgb = WHITE

    def add_card(slide, left, top, width, height, title, body_lines, accent_color=CYAN, bg_color=CARD_BG):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        card.line.color.rgb = accent_color
        card.line.width = Pt(1.5)

        tb = slide.shapes.add_textbox(left + Inches(0.2), top + Inches(0.15), width - Inches(0.4), height - Inches(0.3))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.vertical_anchor = MSO_ANCHOR.TOP

        # Card Title
        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.bold = True
        p0.font.size = Pt(15)
        p0.font.color.rgb = accent_color
        p0.space_after = Pt(8)

        # Card Body Lines
        for line in body_lines:
            p = tf.add_paragraph()
            p.text = line
            p.font.size = Pt(11.5)
            p.font.color.rgb = WHITE if not line.startswith("  -") else MUTED
            p.space_after = Pt(4)

        return card

    # =========================================================================
    # SLIDE 1: Title Slide (Hero)
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    add_bg(s1)

    # Decorative top bar
    bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(0.12))
    bar.fill.solid()
    bar.fill.fore_color.rgb = CYAN
    bar.line.fill.background()

    # Title box
    tb = s1.shapes.add_textbox(Inches(1.0), Inches(1.8), Inches(11.3), Inches(3.0))
    tf = tb.text_frame
    tf.word_wrap = True

    p_badge = tf.paragraphs[0]
    p_badge.text = "COMPUTER NETWORKS  |  END ASSIGNMENT 8"
    p_badge.font.bold = True
    p_badge.font.size = Pt(13)
    p_badge.font.color.rgb = CYAN
    p_badge.space_after = Pt(12)

    p_main = tf.add_paragraph()
    p_main.text = "Modular Data Link Layer Simulation"
    p_main.font.bold = True
    p_main.font.size = Pt(36)
    p_main.font.color.rgb = WHITE
    p_main.space_after = Pt(10)

    p_sub = tf.add_paragraph()
    p_sub.text = "CSMA/CA (MAC)  •  Go-Back-N ARQ (Flow Control)  •  Hamming Codes (Error Control)"
    p_sub.font.size = Pt(18)
    p_sub.font.color.rgb = INDIGO
    p_sub.space_after = Pt(20)

    p_desc = tf.add_paragraph()
    p_desc.text = "Full C++ Implementation, Real-Time Console Visualizer & PyShark / Wireshark Packet Dissection"
    p_desc.font.size = Pt(13)
    p_desc.font.color.rgb = MUTED

    # Bottom metric badges
    b1 = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.0), Inches(5.6), Inches(3.4), Inches(1.0))
    b1.fill.solid()
    b1.fill.fore_color.rgb = CARD_BG
    b1.line.color.rgb = GREEN
    b1_tb = s1.shapes.add_textbox(Inches(1.1), Inches(5.65), Inches(3.2), Inches(0.9))
    b1_tf = b1_tb.text_frame
    p1 = b1_tf.paragraphs[0]
    p1.text = "Hamming SEC (12,8)"
    p1.font.bold = True
    p1.font.size = Pt(13)
    p1.font.color.rgb = GREEN
    p2 = b1_tf.add_paragraph()
    p2.text = "Single-bit error correction in-place"
    p2.font.size = Pt(10)
    p2.font.color.rgb = MUTED

    b2 = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(4.8), Inches(5.6), Inches(3.4), Inches(1.0))
    b2.fill.solid()
    b2.fill.fore_color.rgb = CARD_BG
    b2.line.color.rgb = AMBER
    b2_tb = s1.shapes.add_textbox(Inches(4.9), Inches(5.65), Inches(3.2), Inches(0.9))
    b2_tf = b2_tb.text_frame
    p1 = b2_tf.paragraphs[0]
    p1.text = "Go-Back-N ARQ (W=4)"
    p1.font.bold = True
    p1.font.size = Pt(13)
    p1.font.color.rgb = AMBER
    p2 = b2_tf.add_paragraph()
    p2.text = "Sliding window, timers & rollback"
    p2.font.size = Pt(10)
    p2.font.color.rgb = MUTED

    b3 = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(8.6), Inches(5.6), Inches(3.7), Inches(1.0))
    b3.fill.solid()
    b3.fill.fore_color.rgb = CARD_BG
    b3.line.color.rgb = CYAN
    b3_tb = s1.shapes.add_textbox(Inches(8.7), Inches(5.65), Inches(3.5), Inches(0.9))
    b3_tf = b3_tb.text_frame
    p1 = b3_tf.paragraphs[0]
    p1.text = "CSMA/CA + PyShark"
    p1.font.bold = True
    p1.font.size = Pt(13)
    p1.font.color.rgb = CYAN
    p2 = b3_tf.add_paragraph()
    p2.text = "RTS/CTS, Backoff & PCAP capture"
    p2.font.size = Pt(10)
    p2.font.color.rgb = MUTED

    # =========================================================================
    # SLIDE 2: System Architecture & Unified Workflow
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    add_bg(s2)
    add_header(s2, "System Architecture", "Unified Three-Pillar Data Link Layer Design")

    add_card(s2, Inches(0.8), Inches(1.6), Inches(3.6), Inches(5.2),
             "1. CSMA/CA (MAC)",
             [
                 "Multiple Access Control:",
                 "• Solves shared medium collision",
                 "• DIFS carrier sensing (150ms)",
                 "• RTS/CTS handshaking (SIFS 50ms)",
                 "• NAV channel reservation timer",
                 "• Binary Exponential Backoff",
                 "  - Random slots on busy channel",
                 "  - CW doubles upon collision",
                 "• Solves Hidden Node Problem"
             ], CYAN)

    add_card(s2, Inches(4.8), Inches(1.6), Inches(3.6), Inches(5.2),
             "2. Go-Back-N (Flow)",
             [
                 "Flow & Reliability Control:",
                 "• Sliding Window of size W = 4",
                 "• Pipelined transmission",
                 "• Visual window states:",
                 "  - [OK] : Acknowledged frame",
                 "  - [~~] : In-flight frame",
                 "  - [  ] : Unsent frame buffer",
                 "• Cumulative ACKs",
                 "• 300ms Timeout Detection",
                 "• Automatic window rollback"
             ], AMBER)

    add_card(s2, Inches(8.8), Inches(1.6), Inches(3.7), Inches(5.2),
             "3. Hamming Code (ECC)",
             [
                 "Error Control (SEC):",
                 "• Parity bits at powers of 2 (1,2,4,8)",
                 "• (12, 8) systematic codeword",
                 "• Injects single-bit channel flips",
                 "• Syndrome Decoding at receiver:",
                 "  - Syndrome = 0 : Clean frame",
                 "  - Syndrome = k : Flip bit k",
                 "• Instant in-place correction",
                 "• Eliminates unnecessary retries"
             ], GREEN)

    # =========================================================================
    # SLIDE 3: Multiple Access Control (CSMA/CA)
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    add_bg(s3)
    add_header(s3, "Multiple Access Sublayer", "CSMA/CA Protocol Mechanics & Collision Avoidance", CYAN)

    add_card(s3, Inches(0.8), Inches(1.6), Inches(5.6), Inches(2.5),
             "Carrier Sensing & Inter-Frame Spaces",
             [
                 "• DIFS (Distributed Inter-Frame Space = 150ms):",
                 "  Node senses channel before attempting any transmission.",
                 "• SIFS (Short Inter-Frame Space = 50ms):",
                 "  High-priority gap between RTS, CTS, DATA, and ACK.",
                 "• Virtual Carrier Sensing via NAV (Network Allocation Vector):",
                 "  Nodes overhear RTS/CTS and defer access until NAV expires."
             ], CYAN)

    add_card(s3, Inches(6.8), Inches(1.6), Inches(5.7), Inches(2.5),
             "Binary Exponential Backoff Algorithm",
             [
                 "• When channel is BUSY, node does not transmit immediately.",
                 "• Contention Window: CW starts at CWmin = 4 slots.",
                 "• Random Backoff = uniform_random(0, CW - 1) slots.",
                 "• Node counts down slot-by-slot (SLOT_MS = 30ms).",
                 "• Upon collision: CW doubles: CW = min(CW * 2, CWmax = 16).",
                 "• Resets back to CWmin after successful transmission."
             ], INDIGO)

    add_card(s3, Inches(0.8), Inches(4.4), Inches(11.7), Inches(2.4),
             "RTS / CTS Handshake Workflow",
             [
                 "Step 1: Node A sends RTS (Request to Send) to Node B (reserves medium).",
                 "Step 2: Node B replies with CTS (Clear to Send) back to Node A after SIFS.",
                 "Step 3: Other nodes (e.g. Node C) overhear CTS and update their NAV timer to stay silent.",
                 "Step 4: Node A securely transmits DATA frame with zero collision from hidden nodes."
             ], PURPLE)

    # =========================================================================
    # SLIDE 4: Flow Control (Go-Back-N ARQ)
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    add_bg(s4)
    add_header(s4, "Flow & Error Control", "Go-Back-N Sliding Window ARQ Protocol", AMBER)

    add_card(s4, Inches(0.8), Inches(1.6), Inches(5.6), Inches(5.2),
             "Sliding Window Architecture (W = 4)",
             [
                 "Key Invariants & Pointers:",
                 "• base: Lowest sequence number not yet acknowledged.",
                 "• nextSeq: Next sequence number to be sent.",
                 "• Window Constraint: nextSeq < base + WINDOW_SIZE.",
                 "",
                 "Real-time Console Tracking:",
                 "  [[OK] [OK] [~~] [~~] [  ] [  ]]",
                 "  - [OK] : Frames 0, 1 confirmed by receiver.",
                 "  - [~~] : Frames 2, 3 in-flight across network.",
                 "  - [  ] : Frames 4, 5 waiting in sender queue.",
                 "",
                 "Cumulative Acknowledgment:",
                 "• ACK(n) confirms all frames up to and including n.",
                 "• Window base slides forward continuously as ACKs arrive."
             ], AMBER)

    add_card(s4, Inches(6.8), Inches(1.6), Inches(5.7), Inches(5.2),
             "Timeout Handling & Window Rollback",
             [
                 "Frame Loss Scenario (Frame #3):",
                 "• Frame #3 is artificially dropped on 1st transmission.",
                 "• Node B receives Frame 0, 1, 2 and sends ACK 0, 1, 2.",
                 "• Receiver discards out-of-order frames to guarantee in-order delivery.",
                 "",
                 "The Rollback Mechanism:",
                 "• Sender timer expires for unacknowledged Frame #3 (300ms).",
                 "• Go-Back-N triggers: nextSeq is reset back to base (3).",
                 "• Sender retransmits Frame #3, followed by 4 and 5.",
                 "",
                 "Mathematical Efficiency:",
                 "• Efficiency η = W / (1 + 2a), where a = Tprop / Ttrans.",
                 "• Outperforms Stop-and-Wait by a factor of W on high-delay links."
             ], ROSE)

    # =========================================================================
    # SLIDE 5: Error Control (Hamming Code SEC)
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    add_bg(s5)
    add_header(s5, "Bit-Level Error Control", "Hamming (12, 8) Single Error Correction (SEC)", GREEN)

    add_card(s5, Inches(0.8), Inches(1.6), Inches(5.6), Inches(5.2),
             "Parity Bit Calculation & Codeword Structure",
             [
                 "Mathematical Invariant:",
                 "• Minimum parity bits r satisfies: 2^r >= r + m + 1",
                 "• For m = 8 data bits: r = 4 parity bits (2^4 = 16 >= 13).",
                 "• Total codeword length n = m + r = 12 bits.",
                 "",
                 "Bit Positioning Map (1-Indexed):",
                 "• Pos 1, 2, 4, 8 : Parity bits (P1, P2, P4, P8)",
                 "• Pos 3, 5, 6, 7, 9, 10, 11, 12 : Data bits (D1 to D8)",
                 "",
                 "Parity Bit Coverage (Even Parity):",
                 "• P1 checks bits: 1, 3, 5, 7, 9, 11",
                 "• P2 checks bits: 2, 3, 6, 7, 10, 11",
                 "• P4 checks bits: 4, 5, 6, 7, 12",
                 "• P8 checks bits: 8, 9, 10, 11, 12"
             ], GREEN)

    add_card(s5, Inches(6.8), Inches(1.6), Inches(5.7), Inches(5.2),
             "Syndrome Decoding & In-Place Correction",
             [
                 "Syndrome Computation:",
                 "• Receiver re-computes parity checks across received bits:",
                 "  S = (S4 * 8) + (S3 * 4) + (S2 * 2) + S1",
                 "",
                 "Decoding Decision:",
                 "• If S == 0 : Transmission was error-free.",
                 "• If S != 0 : Bit at position S was flipped in transit!",
                 "",
                 "Simulation Demonstration (Frame #2):",
                 "• Original Data    : 01101001 (8 bits)",
                 "• Hamming Codeword : 010111001001 (12 bits)",
                 "• Injected Error   : Bit 2 flipped (000111001001)",
                 "• Receiver Syndrome: S = 2",
                 "• Correction       : Invert bit at index 2 back to '1'.",
                 "• Recovered Data   : 01101001 -> Perfect Match!"
             ], CYAN)

    # =========================================================================
    # SLIDE 6: Modular C++ Codebase Architecture
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    add_bg(s6)
    add_header(s6, "Software Engineering", "Modular C++ Codebase Architecture & Clean Separation", INDIGO)

    add_card(s6, Inches(0.8), Inches(1.6), Inches(3.6), Inches(2.5),
             "common.h",
             [
                 "Shared Data Definitions:",
                 "• Frame, Node, Channel structs",
                 "• Timing intervals (SIFS, DIFS, NAV)",
                 "• Test vectors (NODE_A/C_DATA)",
                 "• Window size & error constants"
             ], CYAN)

    add_card(s6, Inches(4.8), Inches(1.6), Inches(3.6), Inches(2.5),
             "utils.h / utils.cpp",
             [
                 "Cross-Platform Services:",
                 "• Millisecond timestamps",
                 "• Console header banners",
                 "• sleepMs() timing simulation",
                 "• JSON logger & PCAP generator"
             ], GREEN)

    add_card(s6, Inches(8.8), Inches(1.6), Inches(3.7), Inches(2.5),
             "hamming.h / hamming.cpp",
             [
                 "Error Control Module:",
                 "• calcParityBits() & hammingEncode()",
                 "• injectError() physical simulation",
                 "• hammingDecode() & extractData()",
                 "• Step-by-step walkthrough demo"
             ], PURPLE)

    add_card(s6, Inches(0.8), Inches(4.4), Inches(3.6), Inches(2.5),
             "csma_ca.h / csma_ca.cpp",
             [
                 "Multiple Access Module:",
                 "• csmaCaAccess() negotiation",
                 "• randomBackoff() exponential slots",
                 "• sendAck() / sendNack() handling",
                 "• Node C channel contention runner"
             ], AMBER)

    add_card(s6, Inches(4.8), Inches(4.4), Inches(3.6), Inches(2.5),
             "go_back_n.h / go_back_n.cpp",
             [
                 "Flow Control Module:",
                 "• Sliding window maintenance",
                 "• printWindow() visual state bar",
                 "• Timeout detection & recovery",
                 "• Integrated GBN transmission loop"
             ], ROSE)

    add_card(s6, Inches(8.8), Inches(4.4), Inches(3.7), Inches(2.5),
             "main.cpp & build.bat",
             [
                 "Clean Entry Point (< 80 lines):",
                 "• Initializes logging & PCAP output",
                 "• Orchestrates simulation phases",
                 "• Prints execution summary",
                 "• 1-click compilation via build.bat"
             ], INDIGO)

    # =========================================================================
    # SLIDE 7: Real-Time Execution Trace (Dry Run)
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    add_bg(s7)
    add_header(s7, "Execution Verification", "Chronological Dry Run: 5 Key Simulation Phases", PURPLE)

    add_card(s7, Inches(0.8), Inches(1.6), Inches(11.7), Inches(5.2),
             "Complete Step-by-Step Execution Lifecycle",
             [
                 "Phase 1: Educational Hamming Walkthrough",
                 "  - Encodes 8 data bits into 12-bit codeword. Injects bit flip at pos 2. Syndrome = 2 identifies & corrects bit.",
                 "",
                 "Phase 2: CSMA/CA Contention & Normal Window Filling",
                 "  - Node A senses channel (DIFS 150ms) -> IDLE -> sends RTS -> receives CTS after SIFS 50ms.",
                 "  - Frame 0, 1, 2, 3 sent. Channel BUSY triggers random exponential backoff slot countdowns.",
                 "",
                 "Phase 3: Real-Time Error Correction (Frame #2)",
                 "  - Frame #2 transmitted with bit 2 corrupted. Receiver computes Syndrome = 2, corrects bit in memory, saves payload.",
                 "",
                 "Phase 4: Simulated Frame Drop & Go-Back-N Rollback (Frame #3)",
                 "  - Frame #3 lost in transit. Receiver ACKs frames 0, 1, 2 (window slides to base=3).",
                 "  - Frame #3 ACK times out after 300ms -> Rollback triggered -> Retransmits Frame #3, followed by 4 and 5.",
                 "",
                 "Phase 5: Node C Multi-Node Contention",
                 "  - After Node A finishes, Node C senses channel, negotiates RTS/CTS, transmits 2 frames, and receives ACKs."
             ], PURPLE)

    # =========================================================================
    # SLIDE 8: PyShark & Wireshark Deep Packet Dissection
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    add_bg(s8)
    add_header(s8, "Protocol Dissection", "PyShark & Wireshark Native Packet Inspection", CYAN)

    add_card(s8, Inches(0.8), Inches(1.6), Inches(5.6), Inches(5.2),
             "Real PCAP Binary Generation (C++)",
             [
                 "Standard PCAP File Format (`packet_capture.pcap`):",
                 "• 24-byte PCAP Global Header (Magic 0xa1b2c3d4)",
                 "• 16-byte Packet Headers with microsecond timestamps",
                 "",
                 "Multi-Layer Packet Encapsulation:",
                 "• Layer 2 : Ethernet II (Dst: 02:00:00:00:00:02, Src: 02:00...)",
                 "• Layer 3 : IPv4 Header (Src: 127.0.0.1, Dst: 127.0.0.2)",
                 "• Layer 4 : UDP Header (Src Port: 9000, Dst Port: 9000)",
                 "• Payload : Structured JSON Frame Record",
                 "",
                 "Double-Click Wireshark Inspection:",
                 "• Open `packet_capture.pcap` directly in Wireshark GUI!",
                 "• Filter by `udp.port == 9000` to inspect packets."
             ], CYAN)

    add_card(s8, Inches(6.8), Inches(1.6), Inches(5.7), Inches(5.2),
             "Automated PyShark Analyzer Output",
             [
                 "Section 1: CSMA/CA Handshake Flow",
                 "• Tabulates all RTS, CTS, ACK, and NACK frames.",
                 "• ASCII arrow sequence diagram with DIFS gap markers.",
                 "",
                 "Section 2: Sliding Window Dissection",
                 "• Visual sliding window progression after each packet.",
                 "• Wireshark dissection panel for every DATA frame.",
                 "",
                 "Section 3: Bit-Level Hamming Verification",
                 "• 5-step breakdown: Raw Data -> Codeword -> Parity Positions",
                 "  -> Received Bits -> Correction Decision.",
                 "",
                 "Final Summary & Performance Metrics:",
                 "• Complete count of frames, collisions avoided, and rollbacks."
             ], GREEN)

    # =========================================================================
    # SLIDE 9: Performance Metrics & Verification
    # =========================================================================
    s9 = prs.slides.add_slide(blank_layout)
    add_bg(s9)
    add_header(s9, "Results & Verification", "Quantitative Results & Validation Checklist", GREEN)

    # Metric boxes grid
    metrics = [
        ("36", "Total Frames Captured", "18 Sent + 17 Received in PCAP", CYAN),
        ("9", "Collisions Avoided", "Prevented via RTS/CTS Handshakes", INDIGO),
        ("1", "Bit Error Corrected", "Identified by Syndrome = 2 (Hamming)", GREEN),
        ("1", "Go-Back-N Rollback", "Recovered from lost Frame #3 seamlessly", AMBER),
        ("0", "Uncorrected Errors", "Zero data loss across all transmissions", PURPLE),
        ("100%", "In-Order Delivery", "All 8 payloads delivered sequentially", ROSE)
    ]

    for idx, (val, title, subtitle, col) in enumerate(metrics):
        row = idx // 3
        col_idx = idx % 3
        left = Inches(0.8 + col_idx * 4.0)
        top = Inches(1.6 + row * 2.6)

        c = s9.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, Inches(3.7), Inches(2.3))
        c.fill.solid()
        c.fill.fore_color.rgb = CARD_BG
        c.line.color.rgb = col
        c.line.width = Pt(1.5)

        tb = s9.shapes.add_textbox(left + Inches(0.2), top + Inches(0.2), Inches(3.3), Inches(1.9))
        tf = tb.text_frame
        tf.word_wrap = True

        p_val = tf.paragraphs[0]
        p_val.text = val
        p_val.font.bold = True
        p_val.font.size = Pt(36)
        p_val.font.color.rgb = col
        p_val.space_after = Pt(4)

        p_t = tf.add_paragraph()
        p_t.text = title
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = WHITE
        p_t.space_after = Pt(2)

        p_st = tf.add_paragraph()
        p_st.text = subtitle
        p_st.font.size = Pt(10)
        p_st.font.color.rgb = MUTED

    # =========================================================================
    # SLIDE 10: Conclusion & References
    # =========================================================================
    s10 = prs.slides.add_slide(blank_layout)
    add_bg(s10)
    add_header(s10, "Summary & References", "Key Takeaways & Academic References", INDIGO)

    add_card(s10, Inches(0.8), Inches(1.6), Inches(5.6), Inches(5.2),
             "Project Key Takeaways",
             [
                 "1. Synergy of Layer 2 Protocols:",
                 "   Multiple access, flow control, and error control work",
                 "   in harmony to guarantee reliable, collision-free delivery.",
                 "",
                 "2. Practical Value of Hamming SEC:",
                 "   Fixing bit corruptions at the receiver avoids expensive",
                 "   timeout delays and window rollbacks.",
                 "",
                 "3. Clean Modular Architecture:",
                 "   Replacing monolithic 800-line code with focused",
                 "   single-responsibility C++ modules enhances readability.",
                 "",
                 "4. Real-World Dissection with PyShark:",
                 "   Bridging C++ simulation with Wireshark/PyShark PCAP",
                 "   allows professional packet inspection."
             ], CYAN)

    add_card(s10, Inches(6.8), Inches(1.6), Inches(5.7), Inches(5.2),
             "Academic & Standard References",
             [
                 "Textbooks:",
                 "• A. Tanenbaum & D. Wetherall, Computer Networks (5th ed.),",
                 "  Ch. 3: The Data Link Layer & Hamming Codes.",
                 "• B. Forouzan, Data Communications and Networking (5th ed.),",
                 "  Ch. 11: Data Link Control & Sliding Window ARQ.",
                 "• J. Kurose & K. Ross, Computer Networking: A Top-Down Approach,",
                 "  Ch. 6: The Link Layer and LANs.",
                 "",
                 "Standards & Specifications:",
                 "• IEEE 802.11-2020: Wireless LAN Medium Access Control",
                 "  (MAC) and Physical Layer (PHY) Specifications.",
                 "• RFC 793: Transmission Control Protocol (ARQ principles).",
                 "• Wireshark & PyShark API Documentation (https://kiminewt.github.io/pyshark)."
             ], INDIGO)

    output_path = "data_link_layer_presentation.pptx"
    prs.save(output_path)
    print(f"[SUCCESS] Presentation generated successfully: {output_path}")

if __name__ == "__main__":
    create_deck()
