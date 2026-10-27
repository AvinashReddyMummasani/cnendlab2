#ifndef CSMA_CA_H
#define CSMA_CA_H

#include "common.h"
#include "utils.h"
#include "hamming.h"

// Draws random backoff slot uniformly in [0, cw-1]
int randomBackoff(int cw);

// CSMA/CA channel access negotiation (DIFS -> Backoff -> RTS -> SIFS -> CTS)
bool csmaCaAccess(Node& node, Channel& channel, const std::string& destName, int frameSeq);

// Sends an ACK frame from receiver to sender after SIFS
void sendAck(int seq, const std::string& originalSender, const std::string& ackSender);

// Sends a NACK frame from receiver to sender after SIFS
void sendNack(int seq, const std::string& originalSender, const std::string& nackSender);

// Simulates Node C channel contention and transmission under CSMA/CA
void runNodeCContention(Node& nodeC, Channel& channel);

#endif // CSMA_CA_H
