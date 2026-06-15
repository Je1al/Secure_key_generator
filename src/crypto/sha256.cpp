#include "securekg/crypto/sha256.h"

#include <cstring>

namespace securekg::crypto {
namespace {

constexpr std::uint32_t kK[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

inline std::uint32_t rotr(std::uint32_t x, std::uint32_t n) {
  return (x >> n) | (x << (32 - n));
}
inline std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x & y) ^ (~x & z);
}
inline std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}
inline std::uint32_t bsig0(std::uint32_t x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
inline std::uint32_t bsig1(std::uint32_t x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}
inline std::uint32_t ssig0(std::uint32_t x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}
inline std::uint32_t ssig1(std::uint32_t x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

}  // namespace

void Sha256::reset() {
  h_[0] = 0x6a09e667u;
  h_[1] = 0xbb67ae85u;
  h_[2] = 0x3c6ef372u;
  h_[3] = 0xa54ff53au;
  h_[4] = 0x510e527fu;
  h_[5] = 0x9b05688cu;
  h_[6] = 0x1f83d9abu;
  h_[7] = 0x5be0cd19u;
  buffer_len_ = 0;
  total_len_ = 0;
}

void Sha256::process(const std::uint8_t block[kBlockSize]) {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (std::uint32_t(block[i * 4]) << 24) |
           (std::uint32_t(block[i * 4 + 1]) << 16) |
           (std::uint32_t(block[i * 4 + 2]) << 8) |
           (std::uint32_t(block[i * 4 + 3]));
  }
  for (int i = 16; i < 64; ++i)
    w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];

  std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
  std::uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

  for (int i = 0; i < 64; ++i) {
    std::uint32_t t1 = h + bsig1(e) + ch(e, f, g) + kK[i] + w[i];
    std::uint32_t t2 = bsig0(a) + maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
  h_[5] += f;
  h_[6] += g;
  h_[7] += h;
}

void Sha256::update(const std::uint8_t* data, std::size_t len) {
  total_len_ += len;
  if (buffer_len_ > 0) {
    std::size_t need = kBlockSize - buffer_len_;
    std::size_t take = len < need ? len : need;
    std::memcpy(buffer_ + buffer_len_, data, take);
    buffer_len_ += take;
    data += take;
    len -= take;
    if (buffer_len_ == kBlockSize) {
      process(buffer_);
      buffer_len_ = 0;
    }
  }
  while (len >= kBlockSize) {
    process(data);
    data += kBlockSize;
    len -= kBlockSize;
  }
  if (len > 0) {
    std::memcpy(buffer_, data, len);
    buffer_len_ = len;
  }
}

void Sha256::finish(std::uint8_t out[kDigestSize]) {
  std::uint64_t bit_len = total_len_ * 8u;
  std::uint8_t pad = 0x80;
  update(&pad, 1);
  std::uint8_t zero = 0x00;
  while (buffer_len_ != 56) update(&zero, 1);
  std::uint8_t len_be[8];
  for (int i = 0; i < 8; ++i)
    len_be[i] = static_cast<std::uint8_t>((bit_len >> ((7 - i) * 8)) & 0xFF);
  update(len_be, 8);

  for (int i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<std::uint8_t>((h_[i] >> 24) & 0xFF);
    out[i * 4 + 1] = static_cast<std::uint8_t>((h_[i] >> 16) & 0xFF);
    out[i * 4 + 2] = static_cast<std::uint8_t>((h_[i] >> 8) & 0xFF);
    out[i * 4 + 3] = static_cast<std::uint8_t>(h_[i] & 0xFF);
  }
}

std::array<std::uint8_t, Sha256::kDigestSize> Sha256::finish() {
  std::array<std::uint8_t, kDigestSize> out{};
  finish(out.data());
  return out;
}

std::array<std::uint8_t, Sha256::kDigestSize> Sha256::hash(
    const std::uint8_t* data, std::size_t len) {
  Sha256 h;
  h.update(data, len);
  return h.finish();
}

}  // namespace securekg::crypto
