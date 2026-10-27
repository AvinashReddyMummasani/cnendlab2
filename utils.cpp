#include "utils.h"

static std::ofstream gLog;
static std::ofstream gPcap;

std::string currentTimestamp() {
#ifdef _WIN32
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(2) << st.wHour        << ":"
        << std::setw(2) << st.wMinute      << ":"
        << std::setw(2) << st.wSecond      << "."
        << std::setw(3) << st.wMilliseconds;
    return oss.str();
#else
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    auto timer = std::chrono::system_clock::to_time_t(now);
    std::tm bt = *std::gmtime(&timer);
    std::ostringstream oss;
    oss << std::put_time(&bt, "%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
#endif
}

void printBoxHeader(const std::string& title) {
    std::cout << "\n+" << SEP << "+\n";
    int space = 54 - (int)title.size();
    int lp    = space / 2;
    int rp    = space - lp;
    std::cout << "|" << std::string(lp, ' ') << title << std::string(rp, ' ') << "|\n";
    std::cout << "+" << SEP << "+\n";
}

void printSubHeader(const std::string& text) {
    std::cout << "\n  +-- " << text << "\n";
}

void sleepMs(int ms, const std::string& reason) {
    if (!reason.empty())
        std::cout << "    [wait " << ms << "ms | " << reason << "]\n";
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
#endif
}

static void initPcap(const std::string& filename) {
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

static void writePcapPacket(const std::string& payload) {
    if (!gPcap.is_open()) return;

    uint16_t udpLen   = static_cast<uint16_t>(8 + payload.size());
    uint16_t ipLen    = static_cast<uint16_t>(20 + udpLen);
    uint32_t totalLen = 14 + ipLen; // Ethernet (14) + IP (20) + UDP (8) + payload

    static uint32_t sec = 1700000000;
    static uint32_t usec = 0;
    usec += 10000; // 10ms intervals

    uint32_t incl_len = totalLen;
    uint32_t orig_len = totalLen;

    gPcap.write(reinterpret_cast<const char*>(&sec), 4);
    gPcap.write(reinterpret_cast<const char*>(&usec), 4);
    gPcap.write(reinterpret_cast<const char*>(&incl_len), 4);
    gPcap.write(reinterpret_cast<const char*>(&orig_len), 4);

    // 1. Ethernet Header (14 bytes)
    unsigned char eth[14] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,  // Dst MAC
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,  // Src MAC
        0x08, 0x00                           // EtherType: IPv4
    };
    gPcap.write(reinterpret_cast<const char*>(eth), 14);

    // 2. IPv4 Header (20 bytes)
    unsigned char ip[20] = {
        0x45, 0x00,
        static_cast<unsigned char>((ipLen >> 8) & 0xFF),
        static_cast<unsigned char>(ipLen & 0xFF),
        0x00, 0x01,
        0x00, 0x00,
        0x40,                                 // TTL: 64
        0x11,                                 // Protocol: 17 (UDP)
        0x00, 0x00,                           // Checksum placeholder
        127, 0, 0, 1,                         // Src: 127.0.0.1
        127, 0, 0, 2                          // Dst: 127.0.0.2
    };

    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) {
        if (i == 10) continue;
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
        0x00, 0x00
    };
    gPcap.write(reinterpret_cast<const char*>(udp), 8);

    // 4. Payload (JSON string)
    gPcap.write(payload.data(), payload.size());
    gPcap.flush();
}

bool initLogging(const std::string& logFile, const std::string& pcapFile) {
    gLog.open(logFile, std::ios::out | std::ios::trunc);
    initPcap(pcapFile);
    return gLog.is_open() && gPcap.is_open();
}

void closeLogging() {
    if (gLog.is_open())  gLog.close();
    if (gPcap.is_open()) gPcap.close();
}

void logPacket(int seq,
               const std::string& type,
               const std::string& sender,
               const std::string& receiver,
               const std::string& data,
               const std::string& hamming,
               int  errBit,
               bool corrected)
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
