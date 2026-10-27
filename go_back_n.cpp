#include "go_back_n.h"

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

void runGoBackN(Node& nodeA, Node& nodeB, Channel& channel) {
    printBoxHeader("GO-BACK-N ARQ  (Window = " +
                   std::to_string(WINDOW_SIZE) + ")");

    int total     = TOTAL_FRAMES_A;
    int base      = 0;
    int nextSeq   = 0;
    bool lostOnce = false;

    std::vector<bool> acked(total, false);

    while (base < total) {
        // Send Phase: transmit up to WINDOW_SIZE frames
        while (nextSeq < total && nextSeq < base + WINDOW_SIZE) {
            printSubHeader("Sending Frame #" + std::to_string(nextSeq));

            // 1. CSMA/CA Channel Contention
            csmaCaAccess(nodeA, channel, nodeB.name, nextSeq);

            // 2. Hamming Encoding & Error Injection (on ERROR_FRAME)
            bool injectErr = (nextSeq == ERROR_FRAME);
            runHammingForFrame(nextSeq, NODE_A_DATA[nextSeq],
                               injectErr, ERROR_BIT_POS,
                               nodeA.name, nodeB.name);

            // 3. Transmit DATA
            bool lost = (nextSeq == LOST_FRAME) && !lostOnce;
            std::cout << "  " << nodeA.name
                      << " --[DATA " << nextSeq << "]-->"
                      << " " << nodeB.name;
            if (lost)
                std::cout << "   <<< FRAME LOST IN TRANSIT (1st attempt) >>>";
            std::cout << "\n";

            channel.release();
            printWindow(base, nextSeq + 1, total);
            ++nextSeq;
            sleepMs(40);
        }

        // ACK / Timeout Phase
        bool rolledBack = false;
        for (int seq = base; seq < nextSeq && !rolledBack; ++seq) {
            if (acked[seq]) continue;

            bool lost = (seq == LOST_FRAME) && !lostOnce;
            if (lost) {
                // Timeout triggering Go-Back-N rollback
                sleepMs(TIMEOUT_MS, "waiting for ACK (TIMEOUT)");
                std::cout << "  *** TIMEOUT for Frame #" << seq
                          << " -- Go-Back-N rollback to frame "
                          << seq << " ***\n";
                logPacket(seq, "NACK", nodeB.name, nodeA.name);
                lostOnce = true;
                nextSeq  = seq;
                rolledBack = true;
            } else {
                sendAck(seq, nodeA.name, nodeB.name);
                acked[seq] = true;
                while (base < total && acked[base]) ++base;
                printWindow(base, nextSeq, total);
                sleepMs(30);
            }
        }
    }

    std::cout << "\n  All " << total
              << " frames ACKed. Transfer complete.\n";
}
