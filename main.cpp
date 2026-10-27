// =============================================================================
// DATA LINK LAYER SIMULATION — MAIN ENTRY POINT
// Protocols: CSMA/CA + Go-Back-N ARQ + Hamming Code (SEC)
//
// Modular Architecture:
//   - common.h    : Shared structs, constants, and network parameters
//   - utils.h/.cpp : Timestamps, logging, console banners, and PCAP writer
//   - hamming.h/.cpp : Error control (encoding, syndrome, correction)
//   - csma_ca.h/.cpp : Multiple access (carrier sensing, backoff, RTS/CTS)
//   - go_back_n.h/.cpp: Flow control (sliding window, timers, rollback)
// =============================================================================

#include "common.h"
#include "utils.h"
#include "hamming.h"
#include "csma_ca.h"
#include "go_back_n.h"

int main() {
    // ---- Step 1: Initialize Logs and PCAP capture file ----
    if (!initLogging(LOG_FILE, PCAP_FILE)) {
        std::cerr << "Warning: could not open log files.\n";
    } else {
        std::cout << "Packet log  : " << LOG_FILE << "\n";
        std::cout << "PCAP capture: " << PCAP_FILE << " (ready for PyShark / Wireshark)\n";
    }

    // ---- Step 2: Display Simulation Overview Banner ----
    printBoxHeader("DATA LINK LAYER SIMULATION");
    std::cout << "  Protocols    : CSMA/CA + Go-Back-N ARQ + Hamming Code\n";
    std::cout << "  Time         : " << currentTimestamp() << "\n";
    std::cout << "  NodeA->NodeB : " << TOTAL_FRAMES_A << " frames\n";
    std::cout << "  NodeC->NodeB : " << TOTAL_FRAMES_C << " frames (contention)\n";
    std::cout << "  Error frame  : #" << ERROR_FRAME
              << " (bit " << ERROR_BIT_POS << " flipped, Hamming corrects)\n";
    std::cout << "  Lost frame   : #" << LOST_FRAME
              << " (Go-Back-N rollback + retransmit)\n";

    // ---- Phase 1: Hamming Code Educational Walkthrough ----
    hammingWalkthrough();

    // ---- Phase 2: Instantiate Network Nodes and Shared Channel ----
    Node    nodeA("NodeA", NODE_A_DATA);
    Node    nodeB("NodeB", {});            // receiver node
    Node    nodeC("NodeC", NODE_C_DATA);   // competing sender
    Channel channel;

    // ---- Phase 3: Node A -> Node B (CSMA/CA + Go-Back-N + Hamming) ----
    printBoxHeader("INTEGRATED SIMULATION -- NODE A TRANSMITS");
    runGoBackN(nodeA, nodeB, channel);

    // ---- Phase 4: Node C Contention (CSMA/CA Demonstration) ----
    runNodeCContention(nodeC, channel);

    // ---- Phase 5: Final Simulation Summary ----
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

    // Flush and close log & pcap file handles
    closeLogging();
    return 0;
}
