#include "sha_mixer.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

namespace secure_keygen {
namespace {

constexpr std::array<std::uint32_t, 64> k = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
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

inline std::uint32_t big_sigma0(std::uint32_t x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline std::uint32_t big_sigma1(std::uint32_t x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline std::uint32_t small_sigma0(std::uint32_t x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline std::uint32_t small_sigma1(std::uint32_t x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void append_u64(std::vector<uint8_t>& out, std::uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

} // namespace

std::vector<uint8_t> ShaMixer::sha256(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> padded = data;
  std::uint64_t bit_len = static_cast<std::uint64_t>(padded.size()) * 8u;

  // Padding: append 1 bit (0x80), then zeros, then 64-bit length.
  padded.push_back(0x80u);
  while ((padded.size() % 64) != 56) {
    padded.push_back(0x00u);
  }
  append_u64(padded, bit_len);

  std::uint32_t h0 = 0x6a09e667u;
  std::uint32_t h1 = 0xbb67ae85u;
  std::uint32_t h2 = 0x3c6ef372u;
  std::uint32_t h3 = 0xa54ff53au;
  std::uint32_t h4 = 0x510e527fu;
  std::uint32_t h5 = 0x9b05688cu;
  std::uint32_t h6 = 0x1f83d9abu;
  std::uint32_t h7 = 0x5be0cd19u;

  for (std::size_t chunk = 0; chunk < padded.size(); chunk += 64) {
    std::array<std::uint32_t, 64> w{};
    for (int i = 0; i < 16; ++i) {
      std::size_t idx = chunk + (i * 4);
      w[i] = (static_cast<std::uint32_t>(padded[idx]) << 24) |
             (static_cast<std::uint32_t>(padded[idx + 1]) << 16) |
             (static_cast<std::uint32_t>(padded[idx + 2]) << 8) |
             (static_cast<std::uint32_t>(padded[idx + 3]));
    }
    for (int i = 16; i < 64; ++i) {
      w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
    }

    std::uint32_t a = h0;
    std::uint32_t b = h1;
    std::uint32_t c = h2;
    std::uint32_t d = h3;
    std::uint32_t e = h4;
    std::uint32_t f = h5;
    std::uint32_t g = h6;
    std::uint32_t h = h7;

    for (int i = 0; i < 64; ++i) {
      std::uint32_t t1 = h + big_sigma1(e) + ch(e, f, g) + k[i] + w[i];
      std::uint32_t t2 = big_sigma0(a) + maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
    h5 += f;
    h6 += g;
    h7 += h;
  }

  std::vector<uint8_t> digest;
  digest.reserve(32);
  auto append_word = [&digest](std::uint32_t w) {
    digest.push_back(static_cast<uint8_t>((w >> 24) & 0xFFu));
    digest.push_back(static_cast<uint8_t>((w >> 16) & 0xFFu));
    digest.push_back(static_cast<uint8_t>((w >> 8) & 0xFFu));
    digest.push_back(static_cast<uint8_t>(w & 0xFFu));
  };

  append_word(h0);
  append_word(h1);
  append_word(h2);
  append_word(h3);
  append_word(h4);
  append_word(h5);
  append_word(h6);
  append_word(h7);

  return digest;
}

std::vector<uint8_t> ShaMixer::mix(const std::vector<uint8_t>& entropy,
                                   std::size_t out_len,
                                   std::size_t rounds) const {
  std::vector<uint8_t> output;
  output.reserve(out_len);

  std::vector<uint8_t> seed = entropy;
  std::vector<uint8_t> prev;

  for (std::uint64_t counter = 0; output.size() < out_len; ++counter) {
    std::vector<uint8_t> block = seed;
    append_u64(block, counter);
    block.insert(block.end(), prev.begin(), prev.end());

    std::vector<uint8_t> hash = sha256(block);
    for (std::size_t round = 1; round < rounds; ++round) {
      hash = sha256(hash);
    }

    std::size_t take = std::min(hash.size(), out_len - output.size());
    output.insert(output.end(), hash.begin(), hash.begin() + static_cast<std::ptrdiff_t>(take));
    prev = hash;
  }

  return output;
}

} // namespace secure_keygen
