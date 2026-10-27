#ifndef GO_BACK_N_H
#define GO_BACK_N_H

#include "common.h"
#include "utils.h"
#include "hamming.h"
#include "csma_ca.h"

// Renders the sliding window visually: [OK]=acked, [~~]=in-flight, [  ]=unsent
void printWindow(int base, int nextSeq, int total);

// Runs complete Go-Back-N protocol with sliding window, timeout, and rollback
void runGoBackN(Node& nodeA, Node& nodeB, Channel& channel);

#endif // GO_BACK_N_H
