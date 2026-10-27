#ifndef UTILS_H
#define UTILS_H

#include "common.h"

// Returns current timestamp formatted as "HH:MM:SS.mmm"
std::string currentTimestamp();

// Prints prominent section box headers
void printBoxHeader(const std::string& title);

// Prints a sub-section label
void printSubHeader(const std::string& text);

// Cross-platform sleep for milliseconds
void sleepMs(int ms, const std::string& reason = "");

// Initializes log file and PCAP capture file
bool initLogging(const std::string& logFile, const std::string& pcapFile);

// Flushes and closes open log & capture handles
void closeLogging();

// Writes a structured JSON packet record to packet_log.txt and creates a PCAP frame
void logPacket(int seq,
               const std::string& type,
               const std::string& sender,
               const std::string& receiver,
               const std::string& data    = "",
               const std::string& hamming = "",
               int  errBit                = -1,
               bool corrected             = false);

#endif // UTILS_H
