#ifndef HAMMING_H
#define HAMMING_H

#include "common.h"
#include "utils.h"

// Returns true if position is a power of 2 (parity bit position)
bool isPowerOfTwo(int pos);

// Calculates minimal parity bits r such that 2^r >= r + dataBits + 1
int calcParityBits(int dataBits);

// Encodes data string into a Hamming codeword with parity bits
std::string hammingEncode(const std::string& data);

// Flips a single bit at 1-based position bitPos
std::string injectError(const std::string& encoded, int bitPos);

// Computes syndrome, identifies error position, and corrects it
std::pair<std::string, int> hammingDecode(const std::string& recv);

// Strips parity bits and extracts original data payload
std::string extractData(const std::string& cw);

// Full per-frame Hamming pipeline (encode -> error injection -> decode -> log)
std::string runHammingForFrame(int frameSeq,
                               const std::string& data,
                               bool  injectErr,
                               int   errBitPos,
                               const std::string& sender,
                               const std::string& receiver);

// Educational walkthrough showing bit mapping, error injection & correction
void hammingWalkthrough();

#endif // HAMMING_H
