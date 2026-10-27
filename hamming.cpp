#include "hamming.h"

bool isPowerOfTwo(int pos) {
    return (pos > 0) && ((pos & (pos - 1)) == 0);
}

int calcParityBits(int dataBits) {
    int r = 0;
    while ((1 << r) < (r + dataBits + 1)) ++r;
    return r;
}

std::string hammingEncode(const std::string& data) {
    int d = (int)data.size();
    int r = calcParityBits(d);
    int n = d + r;

    std::vector<int> cw(n + 1, 0);

    // Place data bits in non-power-of-2 positions
    int di = 0;
    for (int pos = 1; pos <= n && di < d; ++pos) {
        if (!isPowerOfTwo(pos))
            cw[pos] = data[di++] - '0';
    }

    // Calculate parity bits
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

std::string injectError(const std::string& encoded, int bitPos) {
    std::string bad = encoded;
    if (bitPos >= 1 && bitPos <= (int)bad.size())
        bad[bitPos - 1] = (bad[bitPos - 1] == '0') ? '1' : '0';
    return bad;
}

std::pair<std::string, int> hammingDecode(const std::string& recv) {
    int n = (int)recv.size();
    std::vector<int> cw(n + 1);
    for (int i = 1; i <= n; ++i) cw[i] = recv[i - 1] - '0';

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

std::string extractData(const std::string& cw) {
    std::string data;
    for (int i = 1; i <= (int)cw.size(); ++i) {
        if (!isPowerOfTwo(i)) data += cw[i - 1];
    }
    return data;
}

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

    std::pair<std::string, int> decoded = hammingDecode(transmitted);
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

    std::cout << "\n  Position map (P = parity bit, D = data bit):\n";
    std::cout << "  Pos: ";
    for (int i = 1; i <= n; ++i) std::cout << std::setw(3) << i;
    std::cout << "\n  Bit: ";
    for (int i = 1; i <= n; ++i) std::cout << std::setw(3) << encoded[i-1];
    std::cout << "\n  Typ: ";
    for (int i = 1; i <= n; ++i)
        std::cout << std::setw(3) << (isPowerOfTwo(i) ? "P" : "D");
    std::cout << "\n\n";

    std::string corrupted = injectError(encoded, ERROR_BIT_POS);
    std::cout << "  -- Injecting single-bit error at position "
              << ERROR_BIT_POS << " --\n";
    std::cout << "  Original  : " << encoded   << "\n";
    std::cout << "  Corrupted : " << corrupted << "\n";

    std::pair<std::string, int> res = hammingDecode(corrupted);
    std::string corrected = res.first;
    int         syndrome  = res.second;

    std::cout << "  Syndrome  : " << syndrome
              << "  => error at position " << syndrome << "\n";
    std::cout << "  Corrected : " << corrected << "\n";
    std::cout << "  Data out  : " << extractData(corrected) << "\n";
    bool match = (extractData(corrected) == data);
    std::cout << "  Matches?  : " << (match ? "YES [OK]" : "NO  [!!]") << "\n";
}
