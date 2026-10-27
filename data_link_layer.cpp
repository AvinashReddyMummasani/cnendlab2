// =============================================================================
// DATA LINK LAYER SIMULATION
// Protocols: CSMA/CA  +  Go-Back-N ARQ  +  Hamming Code (Error Control)
//
// Compiler: MinGW GCC 6.3 (Windows) — uses Windows Sleep() instead of
//           std::this_thread::sleep_for (which is broken on MinGW 6.3).
//
// Compile:
//   g++ -std=c++14 data_link_layer.cpp -o data_link_layer
// Run:
//   data_link_layer.exe
// =============================================================================

// ---------- Standard C++ headers ----------
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <utility>      // std::pair, std::make_pair
#include <ctime>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>
#include <algorithm>    // std::min
#include <cstdint>      // uint32_t, uint16_t, uint8_t

// ---------- Windows-specific (for Sleep()) ----------
#include <windows.h>    // Sleep(DWORD ms)

// =============================================================================
// SECTION 0 : GLOBAL CONSTANTS
// =============================================================================

const int WINDOW_SIZE    = 4;   // Go-Back-N sliding window width
const int TOTAL_FRAMES_A = 6;   // frames Node A sends to Node B
const int TOTAL_FRAMES_C = 2;   // frames Node C sends (contention demo)
const int ERROR_FRAME    = 2;   // 0-based index → frame #3 gets Hamming error
const int ERROR_BIT_POS  = 2;   // 1-indexed bit position to flip
const int LOST_FRAME     = 3;   // 0-based index → frame #4 is "lost" (GBN demo)

// Simulated timing (milliseconds).  Kept short so the demo finishes quickly.
const int SIFS_MS        =  50;
const int DIFS_MS        = 150;
const int SLOT_MS        =  30;
const int NAV_MS         = 400;
const int TIMEOUT_MS     = 300;

const std::string LOG_FILE  = "packet_log.txt";       // output log (text format)
const std::string PCAP_FILE = "packet_capture.pcap";  // output packet capture (PCAP format for PyShark/Wireshark)

// 8-bit binary payloads for Node A
const std::vector<std::string> NODE_A_DATA = {
    "10110010",   // frame 0
    "11001010",   // frame 1
    "01101001",   // frame 2  <- error injected (Hamming demo)
    "10010111",   // frame 3  <- lost in transit (Go-Back-N demo)
    "11100001",   // frame 4
    "00101110"    // frame 5
};

// 8-bit binary payloads for Node C
const std::vector<std::string> NODE_C_DATA = {
    "11010100",
    "00110011"
};

// =============================================================================
// SECTION 1 : UTILITY — TIMESTAMPS, PRINTING, SLEEP, LOGGING
// =============================================================================

// ASCII-safe box / arrow strings (avoids UTF-8 multi-byte render issues on
// some Windows terminals; swap for the UTF-8 versions if your terminal supports them)
static const std::string SEP    = "======================================================"; // 54 chars
static const std::string THIN   = "------------------------------------------------------";
static const std::string ARR    = "-->"; // arrow
static const std::string CHK    = "[OK]";
static const std::string INFLT  = "[~~]";
static const std::string UNSENT = "[  ]";

// Returns current UTC time as "HH:MM:SS.mmm"
std::string currentTimestamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(2) << st.wHour        << ":"
        << std::setw(2) << st.wMinute      << ":"
        << std::setw(2) << st.wSecond      << "."
        << std::setw(3) << st.wMilliseconds;
    return oss.str();
}

// Prints a wide box header for major sections.
void printBoxHeader(const std::string& title) {
    std::cout << "\n+" << SEP << "+\n";
    int space = 54 - (int)title.size();
    int lp    = space / 2;
    int rp    = space - lp;
    std::cout << "|" << std::string(lp,' ') << title << std::string(rp,' ') << "|\n";
    std::cout << "+" << SEP << "+\n";
}

// Prints a thin sub-section label.
void printSubHeader(const std::string& text) {
    std::cout << "\n  +-- " << text << "\n";
}

// Sleeps for 'ms' milliseconds (uses Windows API to avoid MinGW thread issues).
void sleepMs(int ms, const std::string& reason = "") {
    if (!reason.empty())
        std::cout << "    [wait " << ms << "ms | " << reason << "]\n";
    Sleep((DWORD)ms);
}

// ---------- Global log files ----------
std::ofstream gLog;
std::ofstream gPcap;

// Initialize standard PCAP file with 24-byte global header
void initPcap(const std::string& filename) {
    gPcap.open(filename, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!gPcap.is_open()) return;

    // Standard PCAP Global Header: 24 bytes (little-endian)
    uint32_t magic = 0xa1b2c3d4;
    uint16_t v_maj = 2;
    uint16_t v_min = 4;
    int32_t  zone  = 0;
    uint32_t sig   = 0;
    uint32_t snap  = 65535;
    uint32_t net   = 1; // LINKTYPE_ETHERNET

    gPcap.write(reinterpret_cast<const char*>(&magic), 4);
    gPcap.write(reinterpret_cast<const char*>(&v_maj), 2);
    gPcap.write(reinterpret_cast<const char*>(&v_min), 2);
    gPcap.write(reinterpret_cast<const char*>(&zone),  4);
    gPcap.write(reinterpret_cast<const char*>(&sig),   4);
    gPcap.write(reinterpret_cast<const char*>(&snap),  4);
    gPcap.write(reinterpret_cast<const char*>(&net),   4);
    gPcap.flush();
}

// Writes a single frame into the PCAP file as an Ethernet -> IPv4 -> UDP packet
void writePcapPacket(const std::string& payload) {
    if (!gPcap.is_open()) return;

    uint16_t udpLen   = static_cast<uint16_t>(8 + payload.size());
    uint16_t ipLen    = static_cast<uint16_t>(20 + udpLen);
    uint32_t totalLen = 14 + ipLen; // Ethernet (14) + IP (20) + UDP (8) + payload

    // PCAP packet header (16 bytes)
    static uint32_t sec = 1700000000;
    static uint32_t usec = 0;
    usec += 10000; // increment timestamp by 10ms for each packet
    uint32_t incl_len = totalLen;
    uint32_t orig_len = totalLen;

    gPcap.write(reinterpret_cast<const char*>(&sec), 4);
    gPcap.write(reinterpret_cast<const char*>(&usec), 4);
    gPcap.write(reinterpret_cast<const char*>(&incl_len), 4);
    gPcap.write(reinterpret_cast<const char*>(&orig_len), 4);

    // 1. Ethernet Header (14 bytes)
    // Dst MAC: 02:00:00:00:00:02, Src MAC: 02:00:00:00:00:01, EtherType: 0x0800 (IPv4)
    unsigned char eth[14] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x00
    };
    gPcap.write(reinterpret_cast<const char*>(eth), 14);

    // 2. IPv4 Header (20 bytes)
    unsigned char ip[20] = {
        0x45, 0x00,                                   // Version (4), IHL (5), DSCP/ECN (0)
        static_cast<unsigned char>((ipLen >> 8) & 0xFF),
        static_cast<unsigned char>(ipLen & 0xFF),     // Total length
        0x00, 0x01,                                   // Identification
        0x00, 0x00,                                   // Flags, Fragment offset
        0x40,                                         // TTL (64)
        0x11,                                         // Protocol: 17 (UDP)
        0x00, 0x00,                                   // Checksum placeholder
        127, 0, 0, 1,                                 // Src: 127.0.0.1
        127, 0, 0, 2                                  // Dst: 127.0.0.2
    };
    // IPv4 checksum calculation
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) {
        if (i == 10) continue; // skip checksum field
        sum += (static_cast<uint16_t>(ip[i]) << 8) | ip[i+1];
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t csum = ~static_cast<uint16_t>(sum);
    ip[10] = static_cast<unsigned char>((csum >> 8) & 0xFF);
    ip[11] = static_cast<unsigned char>(csum & 0xFF);
    gPcap.write(reinterpret_cast<const char*>(ip), 20);

    // 3. UDP Header (8 bytes)
    uint16_t srcPort = 9000;
    uint16_t dstPort = 9000;
    unsigned char udp[8] = {
        static_cast<unsigned char>((srcPort >> 8) & 0xFF),
        static_cast<unsigned char>(srcPort & 0xFF),
        static_cast<unsigned char>((dstPort >> 8) & 0xFF),
        static_cast<unsigned char>(dstPort & 0xFF),
        static_cast<unsigned char>((udpLen >> 8) & 0xFF),
        static_cast<unsigned char>(udpLen & 0xFF),
        0x00, 0x00                                    // UDP checksum optional
    };
    gPcap.write(reinterpret_cast<const char*>(udp), 8);

    // 4. Payload (JSON packet string)
    gPcap.write(payload.data(), payload.size());
    gPcap.flush();
}

// Writes one JSON-like packet record to the log file and PCAP capture.
void logPacket(int seq,
               const std::string& type,
               const std::string& sender,
               const std::string& receiver,
               const std::string& data    = "",
               const std::string& hamming = "",
               int  errBit                = -1,
               bool corrected             = false)
{
    std::ostringstream ss;
    ss << "{\"seq\": "        << seq
       << ", \"type\": \""    << type     << "\""
       << ", \"sender\": \""  << sender   << "\""
       << ", \"receiver\": \""<< receiver << "\""
       << ", \"data\": \""    << data     << "\""
       << ", \"hamming\": \"" << hamming  << "\""
       << ", \"error_bit\": " << errBit
       << ", \"corrected\": " << (corrected ? "true" : "false")
       << ", \"timestamp\": \""<< currentTimestamp() << "\""
       << "}";

    std::string jsonStr = ss.str();

    if (gLog.is_open()) {
        gLog << jsonStr << "\n";
        gLog.flush();
    }
    writePcapPacket(jsonStr);
}

// =============================================================================
// SECTION 2 : HAMMING CODE — ERROR CONTROL
// =============================================================================
//
// Hamming codes achieve single-bit error *detection and correction* by
// inserting parity bits at power-of-2 positions (1, 2, 4, 8, …) in the
// codeword.  At the receiver, re-computing these parities yields a
// "syndrome" whose integer value equals the position of the flipped bit
// (or 0 if the frame arrived intact).
//
// All position indices in this section are 1-based (standard convention).

// Returns true when 'pos' is a power of two (a parity-bit location).
bool isPowerOfTwo(int pos) {
    return (pos > 0) && ((pos & (pos - 1)) == 0);
}

// Determines the minimum number of parity bits 'r' satisfying:
//   2^r  >=  r + dataBits + 1
int calcParityBits(int dataBits) {
    int r = 0;
    while ((1 << r) < (r + dataBits + 1)) ++r;
    return r;
}

// Encodes a binary-string data payload into a Hamming codeword.
//
// Steps:
//   1. Allocate a codeword array of length n = dataBits + parityBits.
//   2. Scatter data bits into non-power-of-2 positions (left to right).
//   3. For each parity position p = 1,2,4,…:
//        XOR all codeword positions whose index has bit log2(p) set,
//        excluding p itself; store result in cw[p].
std::string hammingEncode(const std::string& data) {
    int d = (int)data.size();
    int r = calcParityBits(d);
    int n = d + r;

    std::vector<int> cw(n + 1, 0);   // 1-indexed; cw[0] unused

    // Step 1 & 2: place data bits
    int di = 0;
    for (int pos = 1; pos <= n && di < d; ++pos) {
        if (!isPowerOfTwo(pos))
            cw[pos] = data[di++] - '0';
    }

    // Step 3: compute parity bits
    for (int p = 1; p <= n; p <<= 1) {
        int par = 0;
        for (int pos = 1; pos <= n; ++pos) {
            if ((pos & p) && pos != p)
                par ^= cw[pos];
        }
        cw[p] = par;
    }

    std::string enc;
    enc.reserve(n);
    for (int i = 1; i <= n; ++i) enc += (char)('0' + cw[i]);
    return enc;
}

// Flips the bit at 1-indexed position 'bitPos' in 'encoded'.
// Simulates a single-bit transmission error.
std::string injectError(const std::string& encoded, int bitPos) {
    std::string bad = encoded;
    if (bitPos >= 1 && bitPos <= (int)bad.size())
        bad[bitPos - 1] = (bad[bitPos - 1] == '0') ? '1' : '0';
    return bad;
}

// Decodes a (possibly corrupted) Hamming codeword.
// Returns {corrected_codeword, syndrome}.
// Syndrome == 0  →  no error detected.
// Syndrome == k  →  bit at position k was flipped; it is corrected in-place.
std::pair<std::string, int> hammingDecode(const std::string& recv) {
    int n = (int)recv.size();
    std::vector<int> cw(n + 1);
    for (int i = 1; i <= n; ++i) cw[i] = recv[i - 1] - '0';

    // Compute syndrome: each parity position p contributes its bit to syndrome
    // if the XOR of all positions it covers (including itself) is non-zero.
    int syndrome = 0;
    for (int p = 1; p <= n; p <<= 1) {
        int par = 0;
        for (int pos = p; pos <= n; ++pos) {
            if (pos & p) par ^= cw[pos];
        }
        if (par) syndrome += p;
    }

    std::string corrected = recv;
    if (syndrome >= 1 && syndrome <= n)
        corrected[syndrome - 1] = (corrected[syndrome - 1] == '0') ? '1' : '0';

    return std::make_pair(corrected, syndrome);
}

// Strips parity-bit positions from a codeword, returning the original data.
std::string extractData(const std::string& cw) {
    std::string data;
    for (int i = 1; i <= (int)cw.size(); ++i) {
        if (!isPowerOfTwo(i)) data += cw[i - 1];
    }
    return data;
}

// Per-frame Hamming encode/decode helper — called inside the GBN loop.
// Prints: original → encoded → transmitted (±error) → syndrome → corrected.
// Returns the corrected codeword.
std::string runHammingForFrame(int frameSeq,
                               const std::string& data,
                               bool  injectErr,
                               int   errBitPos,
                               const std::string& sender,
                               const std::string& receiver)
{
    printSubHeader("Hamming Code -- Frame #" + std::to_string(frameSeq));

    std::string encoded = hammingEncode(data);
    std::cout << "    Original data   : " << data    << "  (" << data.size()    << " bits)\n";
    std::cout << "    Hamming encoded : " << encoded << "  (" << encoded.size() << " bits)\n";

    std::string transmitted = encoded;
    int         actualErr   = -1;
    if (injectErr) {
        actualErr   = errBitPos;
        transmitted = injectError(encoded, errBitPos);
        std::cout << "    *** ERROR INJECTED at bit " << errBitPos << " ***\n";
        std::cout << "    Transmitted     : " << transmitted << "\n";
    } else {
        std::cout << "    Transmitted     : " << transmitted << "  (no error)\n";
    }

    // Decode at receiver side
    std::pair<std::string,int> decoded = hammingDecode(transmitted);
    std::string corrected = decoded.first;
    int         syndrome  = decoded.second;
    bool        hadError  = (syndrome != 0);

    std::cout << "    Syndrome        : " << syndrome;
    if (syndrome == 0)
        std::cout << "  (no error detected)\n";
    else
        std::cout << "  --> error at bit position " << syndrome << " (corrected)\n";

    if (hadError) {
        std::cout << "    Corrected CW    : " << corrected << "\n";
        std::cout << "    Recovered data  : " << extractData(corrected) << "\n";
    }

    logPacket(frameSeq, "DATA", sender, receiver,
              data, encoded, actualErr, hadError);
    return corrected;
}

// =============================================================================
// SECTION 3 : DATA STRUCTURES
// =============================================================================

// One network frame (data or control).
struct Frame {
    int         seq;          // sequence number (0-indexed)
    std::string data;         // raw binary payload
    std::string encoded;      // Hamming codeword
    std::string type;         // "DATA" | "ACK" | "NACK" | "RTS" | "CTS"
    std::string sender;
    std::string receiver;
    bool        lost;         // simulate frame loss (no ACK)
    bool        errInjected;  // single-bit error was injected
    int         errBit;       // which bit position (-1 = none)
};

// Shared wireless channel — all nodes see the same Channel object.
struct Channel {
    bool busy;         // currently being used by some node
    // We track NAV expiry using a simple "expiry time" integer (ms from epoch)
    // Using chrono steady_clock for NAV.
    std::chrono::steady_clock::time_point navEnd;

    Channel() : busy(false) {
        navEnd = std::chrono::steady_clock::now();
    }

    // True when neither the busy flag is set nor the NAV is active.
    bool isFree() const {
        return !busy && (std::chrono::steady_clock::now() >= navEnd);
    }

    // Marks channel busy and sets NAV to expire 'ms' ms from now.
    void reserve(int ms) {
        busy   = true;
        navEnd = std::chrono::steady_clock::now() +
                 std::chrono::milliseconds(ms);
    }

    void release() { busy = false; }
};

// A network node participating in the simulation.
struct Node {
    std::string              name;     // "NodeA", "NodeB", "NodeC"
    std::vector<std::string> txQueue;  // outgoing data payloads
    int                      backoff;  // current backoff slot count
    int                      cw;       // current contention window size

    Node(const std::string& n, const std::vector<std::string>& data)
        : name(n), txQueue(data), backoff(0), cw(4) {}
};

// =============================================================================
// SECTION 4 : CSMA/CA — CARRIER SENSE MULTIPLE ACCESS WITH COLLISION AVOIDANCE
// =============================================================================
//
// IEEE 802.11-style CSMA/CA with RTS/CTS handshake:
//
//   1. Sense channel for DIFS.
//   2. If channel is busy (or NAV active):
//        draw random backoff in [0, CW-1];
//        count down slot by slot (each slot = SLOT_MS);
//        double CW for next collision (binary exponential backoff, max 64).
//   3. Send RTS → sets NAV (reserves channel for other nodes).
//   4. After SIFS → receive CTS from destination.
//   5. After SIFS → proceed with DATA transmission.
//   6. After DATA → after SIFS → receive ACK.

// Fixed-seed RNG produces reproducible output every run.
std::mt19937 rng(42);

// Random backoff slot count drawn uniformly from [0, cw-1].
int randomBackoff(int cw) {
    std::uniform_int_distribution<int> dist(0, cw - 1);
    return dist(rng);
}

// Executes one CSMA/CA negotiation for 'node' wanting to transmit to 'destName'.
// Returns true when channel access is granted.
bool csmaCaAccess(Node& node, Channel& channel,
                  const std::string& destName, int frameSeq)
{
    std::cout << "\n  " << node.name << "  wants to send Frame #"
              << frameSeq << " to " << destName << "\n";

    // --- Step 1: Sense for DIFS ---
    printSubHeader("CSMA/CA channel sense (DIFS)");
    sleepMs(DIFS_MS, "DIFS");

    // --- Step 2: Backoff if channel is busy ---
    if (!channel.isFree()) {
        std::cout << "    Channel BUSY -- entering binary exponential backoff\n";
        node.backoff = randomBackoff(node.cw);
        std::cout << "    CW = " << node.cw
                  << "  backoff slots = " << node.backoff << "\n";
        for (int s = node.backoff; s > 0; --s) {
            std::cout << "      slot countdown: " << s << "\n";
            sleepMs(SLOT_MS);
        }
        node.cw = std::min(node.cw * 2, 16);   // double CW, cap at 16 (demo)
    } else {
        std::cout << "    Channel IDLE\n";
    }

    // --- Step 3: Send RTS (reserves channel / NAV) ---
    channel.reserve(NAV_MS);
    std::cout << "  " << node.name << " --[RTS]--> " << destName << "\n";
    logPacket(frameSeq, "RTS", node.name, destName);
    sleepMs(SIFS_MS, "SIFS");

    // --- Step 4: Receive CTS ---
    std::cout << "  " << destName << " --[CTS]--> " << node.name << "\n";
    logPacket(frameSeq, "CTS", destName, node.name);
    sleepMs(SIFS_MS, "SIFS");

    // Reset CW to minimum after a successful exchange (802.11 standard behaviour)
    node.cw = 4;

    return true;   // channel successfully acquired
}

// Sends an ACK from the receiver back to the original sender.
void sendAck(int seq,
             const std::string& originalSender,
             const std::string& ackSender)
{
    sleepMs(SIFS_MS, "SIFS");
    std::cout << "  " << ackSender
              << " --[ACK " << seq << "]--> "
              << originalSender << "\n";
    logPacket(seq, "ACK", ackSender, originalSender);
}

// Sends a NACK from the receiver back to the original sender.
void sendNack(int seq,
              const std::string& originalSender,
              const std::string& nackSender)
{
    sleepMs(SIFS_MS, "SIFS");
    std::cout << "  " << nackSender
              << " --[NACK " << seq << "]--> "
              << originalSender << "\n";
    logPacket(seq, "NACK", nackSender, originalSender);
}

// =============================================================================
// SECTION 5 : GO-BACK-N ARQ — RELIABLE DELIVERY / FLOW CONTROL
// =============================================================================
//
// Go-Back-N sliding window protocol:
//
//   • Sender maintains a window of WINDOW_SIZE "in-flight" frames.
//   • 'base'    = lowest unACKed sequence number (left edge of window).
//   • 'nextSeq' = next sequence number to transmit (right edge + 1).
//   • On ACK(n): mark frame n as ACKed; slide 'base' forward.
//   • On TIMEOUT/NACK: set nextSeq = base (retransmit entire window).
//
// This function integrates CSMA/CA (channel access per frame) and
// Hamming encoding (error control per frame).

// Renders the current window state visually:
//   [OK] = acknowledged   [~~] = in-flight   [  ] = unsent
void printWindow(int base, int nextSeq, int total) {
    std::cout << "    Window: [";
    for (int i = 0; i < total; ++i) {
        if      (i < base)    std::cout << CHK;
        else if (i < nextSeq) std::cout << INFLT;
        else                  std::cout << UNSENT;
        if (i < total - 1) std::cout << " ";
    }
    std::cout << "]  base=" << base
              << "  next=" << nextSeq
              << "  win=[" << base << ".."
              << std::min(base + WINDOW_SIZE - 1, total - 1) << "]\n";
}

// Complete Go-Back-N simulation: Node A sends TOTAL_FRAMES_A frames to Node B.
void runGoBackN(Node& nodeA, Node& nodeB, Channel& channel) {
    printBoxHeader("GO-BACK-N ARQ  (Window = " +
                   std::to_string(WINDOW_SIZE) + ")");

    int total       = TOTAL_FRAMES_A;
    int base        = 0;    // lowest unACKed sequence number
    int nextSeq     = 0;    // next frame to transmit
    bool lostOnce   = false;// track whether the "lost" frame has already been
                            // dropped once — on retransmission it succeeds

    std::vector<bool> acked(total, false);  // acked[i] = true once ACK(i) received

    // Outer loop: keeps running until every frame is ACKed
    while (base < total) {

        // ---- SEND PHASE: fill the window with new frames ----
        while (nextSeq < total && nextSeq < base + WINDOW_SIZE) {
            printSubHeader("Sending Frame #" + std::to_string(nextSeq));

            // 1. CSMA/CA: negotiate channel access
            csmaCaAccess(nodeA, channel, nodeB.name, nextSeq);

            // 2. Hamming: encode, possibly inject error, decode at receiver
            bool injectErr = (nextSeq == ERROR_FRAME);
            runHammingForFrame(nextSeq, NODE_A_DATA[nextSeq],
                               injectErr, ERROR_BIT_POS,
                               nodeA.name, nodeB.name);

            // 3. Simulate DATA frame transmission.
            // Frame LOST_FRAME is dropped only on the FIRST attempt.
            // On retransmission (lostOnce == true) it arrives normally.
            bool lost = (nextSeq == LOST_FRAME) && !lostOnce;
            std::cout << "  " << nodeA.name
                      << " --[DATA " << nextSeq << "]-->"
                      << " " << nodeB.name;
            if (lost)
                std::cout << "   <<< FRAME LOST IN TRANSIT (1st attempt) >>>";
            std::cout << "\n";

            channel.release();           // release channel after sending DATA
            printWindow(base, nextSeq + 1, total);
            ++nextSeq;
            sleepMs(40);
        }

        // ---- ACK / TIMEOUT PHASE ----
        bool rolledBack = false;

        for (int seq = base; seq < nextSeq && !rolledBack; ++seq) {
            if (acked[seq]) continue;

            // Frame is "lost" only on its first-ever transmission attempt
            bool lost = (seq == LOST_FRAME) && !lostOnce;

            if (lost) {
                // Timeout: no ACK arrives → Go-Back-N rollback
                sleepMs(TIMEOUT_MS, "waiting for ACK (TIMEOUT)");
                std::cout << "  *** TIMEOUT for Frame #" << seq
                          << " -- Go-Back-N rollback to frame "
                          << seq << " ***\n";
                logPacket(seq, "NACK", nodeB.name, nodeA.name);
                lostOnce = true;     // frame is retransmitted → won't be lost again
                nextSeq  = seq;      // roll back transmit pointer
                rolledBack = true;
            } else {
                // Frame received correctly → cumulative ACK
                sendAck(seq, nodeA.name, nodeB.name);
                acked[seq] = true;
                // Slide 'base' forward past all consecutive ACKed frames
                while (base < total && acked[base]) ++base;
                printWindow(base, nextSeq, total);
                sleepMs(30);
            }
        }
    }

    std::cout << "\n  All " << total
              << " frames ACKed. Transfer complete.\n";
}

// =============================================================================
// SECTION 6 : NODE C CSMA/CA CONTENTION DEMO
// =============================================================================
//
// Demonstrates NAV-based deferral: while Node A has reserved the channel,
// Node C senses it as busy, backs off, then eventually gains access after
// the NAV expires.

void runNodeCContention(Node& nodeC, Channel& channel) {
    printBoxHeader("CSMA/CA CONTENTION -- NODE C");

    for (int i = 0; i < TOTAL_FRAMES_C; ++i) {
        csmaCaAccess(nodeC, channel, "NodeB", i);

        std::string encoded = hammingEncode(NODE_C_DATA[i]);
        std::cout << "  " << nodeC.name
                  << " --[DATA " << i << " : " << NODE_C_DATA[i] << "]--> NodeB\n";
        std::cout << "    Hamming encoded : " << encoded << "\n";
        logPacket(i, "DATA", nodeC.name, "NodeB",
                  NODE_C_DATA[i], encoded, -1, false);

        channel.release();
        sendAck(i, nodeC.name, "NodeB");
        sleepMs(80);
    }
}

// =============================================================================
// SECTION 7 : STANDALONE HAMMING WALKTHROUGH (EDUCATIONAL)
// =============================================================================
//
// Shown once at the start so the reader understands the algorithm before
// it is embedded inside the Go-Back-N simulation loop.

void hammingWalkthrough() {
    printBoxHeader("HAMMING CODE -- STEP-BY-STEP WALKTHROUGH");

    std::string data    = NODE_A_DATA[ERROR_FRAME];
    int         d       = (int)data.size();
    int         r       = calcParityBits(d);
    std::string encoded = hammingEncode(data);
    int         n       = (int)encoded.size();

    std::cout << "\n  Data bits    : " << data    << "  (" << d << " bits)\n";
    std::cout << "  Parity bits  : " << r << "\n";
    std::cout << "  Codeword len : " << n << " bits\n";
    std::cout << "  Encoded CW   : " << encoded  << "\n";

    // Print position-type mapping
    std::cout << "\n  Position map (P = parity bit, D = data bit):\n";
    std::cout << "  Pos: ";
    for (int i = 1; i <= n; ++i) std::cout << std::setw(3) << i;
    std::cout << "\n  Bit: ";
    for (int i = 1; i <= n; ++i) std::cout << std::setw(3) << encoded[i-1];
    std::cout << "\n  Typ: ";
    for (int i = 1; i <= n; ++i)
        std::cout << std::setw(3) << (isPowerOfTwo(i) ? "P" : "D");
    std::cout << "\n\n";

    // Inject error and demonstrate correction
    std::string corrupted = injectError(encoded, ERROR_BIT_POS);
    std::cout << "  -- Injecting single-bit error at position "
              << ERROR_BIT_POS << " --\n";
    std::cout << "  Original  : " << encoded   << "\n";
    std::cout << "  Corrupted : " << corrupted << "\n";

    std::pair<std::string,int> res = hammingDecode(corrupted);
    std::string corrected = res.first;
    int         syndrome  = res.second;

    std::cout << "  Syndrome  : " << syndrome
              << "  => error at position " << syndrome << "\n";
    std::cout << "  Corrected : " << corrected << "\n";
    std::cout << "  Data out  : " << extractData(corrected) << "\n";
    bool match = (extractData(corrected) == data);
    std::cout << "  Matches?  : " << (match ? "YES [OK]" : "NO  [!!]") << "\n";
}

// =============================================================================
// SECTION 8 : MAIN — INTEGRATED SIMULATION WORKFLOW
// =============================================================================

int main() {
    // ---- Open log file and PCAP capture file ----
    gLog.open(LOG_FILE, std::ios::out | std::ios::trunc);
    if (!gLog.is_open())
        std::cerr << "Warning: could not open " << LOG_FILE << "\n";
    else
        std::cout << "Packet log  : " << LOG_FILE << "\n";

    initPcap(PCAP_FILE);
    if (gPcap.is_open())
        std::cout << "PCAP capture: " << PCAP_FILE << " (ready for PyShark / Wireshark)\n";

    // ---- Banner ----
    printBoxHeader("DATA LINK LAYER SIMULATION");
    std::cout << "  Protocols : CSMA/CA + Go-Back-N ARQ + Hamming Code\n";
    std::cout << "  Time      : " << currentTimestamp() << "\n";
    std::cout << "  NodeA->NodeB : " << TOTAL_FRAMES_A << " frames\n";
    std::cout << "  NodeC->NodeB : " << TOTAL_FRAMES_C << " frames (contention)\n";
    std::cout << "  Error frame  : #" << ERROR_FRAME
              << " (bit " << ERROR_BIT_POS << " flipped, Hamming corrects)\n";
    std::cout << "  Lost frame   : #" << LOST_FRAME
              << " (Go-Back-N rollback + retransmit)\n";

    // ---- Phase 1: Hamming educational walkthrough ----
    hammingWalkthrough();

    // ---- Phase 2: Build nodes and shared channel ----
    Node    nodeA("NodeA", NODE_A_DATA);
    Node    nodeB("NodeB", {});            // receiver only
    Node    nodeC("NodeC", NODE_C_DATA);
    Channel channel;

    // ---- Phase 3: Node A -> Node B (CSMA/CA + Go-Back-N + Hamming) ----
    printBoxHeader("INTEGRATED SIMULATION -- NODE A TRANSMITS");
    runGoBackN(nodeA, nodeB, channel);

    // ---- Phase 4: Node C contention (CSMA/CA demo) ----
    runNodeCContention(nodeC, channel);

    // ---- Phase 5: Summary ----
    printBoxHeader("SIMULATION COMPLETE");
    std::cout << "  NodeA->NodeB : " << TOTAL_FRAMES_A
              << " frames delivered (GBN retransmitted frame #"
              << LOST_FRAME << ")\n";
    std::cout << "  NodeC->NodeB : " << TOTAL_FRAMES_C
              << " frames delivered (after CSMA/CA deferral)\n";
    std::cout << "  Hamming      : corrected 1-bit error in frame #"
              << ERROR_FRAME << " at bit " << ERROR_BIT_POS << "\n";
    std::cout << "  Go-Back-N    : recovered from lost frame #"
              << LOST_FRAME << " via timeout + rollback\n";
    std::cout << "  Packet log   : " << LOG_FILE << "\n";
    std::cout << "  PCAP capture : " << PCAP_FILE << "\n";
    std::cout << "  Ended at     : " << currentTimestamp() << "\n\n";

    if (gLog.is_open())  gLog.close();
    if (gPcap.is_open()) gPcap.close();
    return 0;
}
