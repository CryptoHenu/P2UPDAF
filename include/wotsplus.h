#ifndef WOTS_PLUS_H
#define WOTS_PLUS_H

#include <vector>
#include <cstdint>
#include <string>

class WOTSPlus {
public:
    static constexpr int n = 32;
    static constexpr int w = 16;
    static constexpr int log_w = 4;
    static constexpr int len_1 = (8 * n) / log_w;
    static constexpr int len_2 = (int)(floor(log2(len_1 * (w - 1)) / log_w)) + 1;
    static constexpr int len = len_1 + len_2;

    using ByteVec = std::vector<uint8_t>;
    using KeyVec = std::vector<ByteVec>;

    // 生成随机种子
    static ByteVec generate_seed();

    // 生成密钥对
    static void keygen(const ByteVec& seed, KeyVec& sk, KeyVec& pk);

    // 签名消息
    static KeyVec sign(const ByteVec& message, const KeyVec& sk);

    // 从签名恢复公钥（用于验证）
    static KeyVec derive_public_key(const KeyVec& signature, const ByteVec& message);

    // 公钥比较
    static bool verify(const ByteVec& message, const KeyVec& signature, const KeyVec& pk);

    // 工具函数
    static std::string hex(const ByteVec& data);

private:
    static ByteVec sha256(const ByteVec& input);
    static ByteVec chain(const ByteVec& sk_part, int steps);
    static ByteVec prf(const ByteVec& seed, int i);
    static std::vector<int> base_w(const ByteVec& input, int out_len);
    static std::vector<int> compute_checksum(const std::vector<int>& msg_base_w);
};

#endif // WOTS_PLUS_H
