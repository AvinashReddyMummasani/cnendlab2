#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <utility>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>
#include <algorithm>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#else
#include <thread>
#endif

// =============================================================================
// GLOBAL SIMULATION CONSTANTS & TEST DATA
// =============================================================================

static const int WINDOW_SIZE    = 4;   // Go-Back-N sliding window width
static const int TOTAL_FRAMES_A = 6;   // frames Node A sends to Node B
static const int TOTAL_FRAMES_C = 2;   // frames Node C sends (contention demo)
static const int ERROR_FRAME    = 2;   // 0-based index -> frame #2 gets Hamming error
static const int ERROR_BIT_POS  = 2;   // 1-indexed bit position to flip
static const int LOST_FRAME     = 3;   // 0-based index -> frame #3 is lost in transit

// Simulated timing intervals (in milliseconds)
static const int SIFS_MS        =  50;
static const int DIFS_MS        = 150;
static const int SLOT_MS        =  30;
static const int NAV_MS         = 400;
static const int TIMEOUT_MS     = 300;

// Log & capture filenames
static const std::string LOG_FILE  = "packet_log.txt";
static const std::string PCAP_FILE = "packet_capture.pcap";

// 8-bit binary payloads for Node A
static const std::vector<std::string> NODE_A_DATA = {
    "10110010",   // frame 0
    "11001010",   // frame 1
    "01101001",   // frame 2  <- error injected (Hamming demo)
    "10010111",   // frame 3  <- lost in transit (Go-Back-N demo)
    "11100001",   // frame 4
    "00101110"    // frame 5
};

// 8-bit binary payloads for Node C
static const std::vector<std::string> NODE_C_DATA = {
    "11010100",
    "00110011"
};

// Visual UI formatting tokens
static const std::string SEP    = "======================================================";
static const std::string THIN   = "------------------------------------------------------";
static const std::string ARR    = "-->";
static const std::string CHK    = "[OK]";
static const std::string INFLT  = "[~~]";
static const std::string UNSENT = "[  ]";

// =============================================================================
// DATA STRUCTURES
// =============================================================================

// Represents a frame traversing the channel
struct Frame {
    int         seq;          // sequence number (0-indexed)
    std::string data;         // raw binary payload
    std::string encoded;      // Hamming codeword
    std::string type;         // "DATA" | "ACK" | "NACK" | "RTS" | "CTS"
    std::string sender;
    std::string receiver;
    bool        lost;         // simulated frame loss
    bool        errInjected;  // single-bit error was injected
    int         errBit;       // bit position (-1 = none)
};

// Shared wireless medium with NAV reservation
struct Channel {
    bool busy;
    std::chrono::steady_clock::time_point navEnd;

    Channel() : busy(false), navEnd(std::chrono::steady_clock::now()) {}

    bool isFree() const {
        return !busy && (std::chrono::steady_clock::now() >= navEnd);
    }

    void reserve(int ms) {
        busy   = true;
        navEnd = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    }

    void release() {
        busy = false;
    }
};

// Network node participating in CSMA/CA & Go-Back-N
struct Node {
    std::string              name;     // "NodeA", "NodeB", "NodeC"
    std::vector<std::string> txQueue;  // outgoing payloads
    int                      backoff;  // current backoff slot count
    int                      cw;       // contention window size

    Node(const std::string& n, const std::vector<std::string>& data)
        : name(n), txQueue(data), backoff(0), cw(4) {}
};

#endif // COMMON_H
