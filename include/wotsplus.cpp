#include "wotsplus.h"
#include <openssl/sha.h>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>

using namespace std;

using ByteVec = WOTSPlus::ByteVec;
using KeyVec = WOTSPlus::KeyVec;

ByteVec WOTSPlus::generate_seed() {
    ByteVec seed(n);
    FILE* urandom = fopen("/dev/urandom", "rb");
    fread(seed.data(), 1, n, urandom);
    fclose(urandom);
    return seed;
}

ByteVec WOTSPlus::sha256(const ByteVec& input) {
    ByteVec digest(n);
    SHA256(input.data(), input.size(), digest.data());
    return digest;
}

ByteVec WOTSPlus::chain(const ByteVec& sk_part, int steps) {
    ByteVec out = sk_part;
    for (int i = 0; i < steps; ++i)
        out = sha256(out);
    return out;
}

ByteVec WOTSPlus::prf(const ByteVec& seed, int i) {
    ByteVec input(seed);
    input.push_back((i >> 8) & 0xFF);
    input.push_back(i & 0xFF);
    return sha256(input);
}

std::vector<int> WOTSPlus::base_w(const ByteVec& input, int out_len) {
    std::vector<int> result;
    int total = 0, bits = 0;
    for (uint8_t byte : input) {
        total = (total << 8) | byte;
        bits += 8;
        while (bits >= log_w) {
            bits -= log_w;
            result.push_back((total >> bits) & (w - 1));
            if (result.size() == out_len)
                return result;
        }
    }
    return result;
}

std::vector<int> WOTSPlus::compute_checksum(const std::vector<int>& msg_base_w) {
    int csum = 0;
    for (int x : msg_base_w)
        csum += w - 1 - x;

    ByteVec csum_bytes = { static_cast<uint8_t>((csum >> 8) & 0xFF), static_cast<uint8_t>(csum & 0xFF) };
    return base_w(csum_bytes, len_2);
}

void WOTSPlus::keygen(const ByteVec& seed, KeyVec& sk, KeyVec& pk) {
    sk.resize(len);
    pk.resize(len);
    for (int i = 0; i < len; ++i) {
        sk[i] = prf(seed, i);
        pk[i] = chain(sk[i], w - 1);
    }
}

KeyVec WOTSPlus::sign(const ByteVec& message, const KeyVec& sk) {
    ByteVec digest = sha256(message);
    auto msg_base = base_w(digest, len_1);
    auto csum = compute_checksum(msg_base);
    msg_base.insert(msg_base.end(), csum.begin(), csum.end());

    KeyVec signature(len);
    for (int i = 0; i < len; ++i)
        signature[i] = chain(sk[i], msg_base[i]);
    return signature;
}

KeyVec WOTSPlus::derive_public_key(const KeyVec& sig, const ByteVec& message) {
    ByteVec digest = sha256(message);
    auto msg_base = base_w(digest, len_1);
    auto csum = compute_checksum(msg_base);
    msg_base.insert(msg_base.end(), csum.begin(), csum.end());

    KeyVec pk(len);
    for (int i = 0; i < len; ++i)
        pk[i] = chain(sig[i], w - 1 - msg_base[i]);
    return pk;
}

bool WOTSPlus::verify(const ByteVec& message, const KeyVec& signature, const KeyVec& pk) {
    auto derived_pk = derive_public_key(signature, message);
    for (int i = 0; i < len; ++i)
        if (derived_pk[i] != pk[i])
            return false;
    return true;
}

std::string WOTSPlus::hex(const ByteVec& data) {
    std::stringstream ss;
    for (uint8_t b : data)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}
