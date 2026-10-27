#include "csma_ca.h"

static std::mt19937 rng(42);

int randomBackoff(int cw) {
    std::uniform_int_distribution<int> dist(0, cw - 1);
    return dist(rng);
}

bool csmaCaAccess(Node& node, Channel& channel,
                  const std::string& destName, int frameSeq)
{
    std::cout << "\n  " << node.name << "  wants to send Frame #"
              << frameSeq << " to " << destName << "\n";

    // 1. Sense channel for DIFS
    printSubHeader("CSMA/CA channel sense (DIFS)");
    sleepMs(DIFS_MS, "DIFS");

    // 2. Backoff if channel is busy
    if (!channel.isFree()) {
        std::cout << "    Channel BUSY -- entering binary exponential backoff\n";
        node.backoff = randomBackoff(node.cw);
        std::cout << "    CW = " << node.cw
                  << "  backoff slots = " << node.backoff << "\n";
        for (int s = node.backoff; s > 0; --s) {
            std::cout << "      slot countdown: " << s << "\n";
            sleepMs(SLOT_MS);
        }
        node.cw = std::min(node.cw * 2, 16);
    } else {
        std::cout << "    Channel IDLE\n";
    }

    // 3. Send RTS (reserves channel with NAV)
    channel.reserve(NAV_MS);
    std::cout << "  " << node.name << " --[RTS]--> " << destName << "\n";
    logPacket(frameSeq, "RTS", node.name, destName);
    sleepMs(SIFS_MS, "SIFS");

    // 4. Receive CTS
    std::cout << "  " << destName << " --[CTS]--> " << node.name << "\n";
    logPacket(frameSeq, "CTS", destName, node.name);
    sleepMs(SIFS_MS, "SIFS");

    // Reset contention window after successful handshake
    node.cw = 4;
    return true;
}

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
