#include "keygen.h"

#include "entropy_collector.h"
#include "sha_mixer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace secure_keygen {
namespace {

std::string to_hex(const std::vector<uint8_t>& data) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (uint8_t byte : data) {
    out.push_back(kHex[(byte >> 4) & 0x0Fu]);
    out.push_back(kHex[byte & 0x0Fu]);
  }
  return out;
}

std::string to_binary(const std::vector<uint8_t>& data) {
  std::string out;
  out.reserve(data.size() * 8);
  for (uint8_t byte : data) {
    for (int bit = 7; bit >= 0; --bit) {
      out.push_back(((byte >> bit) & 0x01u) ? '1' : '0');
    }
  }
  return out;
}

std::string to_base64(const std::vector<uint8_t>& data) {
  static constexpr char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string out;
  std::size_t i = 0;
  while (i + 2 < data.size()) {
    std::uint32_t triple = (static_cast<std::uint32_t>(data[i]) << 16) |
                           (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                           (static_cast<std::uint32_t>(data[i + 2]));
    out.push_back(kB64[(triple >> 18) & 0x3Fu]);
    out.push_back(kB64[(triple >> 12) & 0x3Fu]);
    out.push_back(kB64[(triple >> 6) & 0x3Fu]);
    out.push_back(kB64[triple & 0x3Fu]);
    i += 3;
  }

  if (i < data.size()) {
    std::uint32_t triple = static_cast<std::uint32_t>(data[i]) << 16;
    out.push_back(kB64[(triple >> 18) & 0x3Fu]);
    if (i + 1 < data.size()) {
      triple |= static_cast<std::uint32_t>(data[i + 1]) << 8;
      out.push_back(kB64[(triple >> 12) & 0x3Fu]);
      out.push_back(kB64[(triple >> 6) & 0x3Fu]);
      out.push_back('=');
    } else {
      out.push_back(kB64[(triple >> 12) & 0x3Fu]);
      out.push_back('=');
      out.push_back('=');
    }
  }

  return out;
}

} // namespace

KeyOutput KeyGenerator::generate(KeySizeBits size_bits) const {
  EntropyCollector collector;
  ShaMixer mixer;

  std::size_t size_bytes = static_cast<std::size_t>(size_bits) / 8;

  // Gather entropy from the OS and system state, then mix with SHA-256.
  std::vector<uint8_t> entropy = collector.collect(64);
  std::vector<uint8_t> key = mixer.mix(entropy, size_bytes, 3);

  KeyOutput output;
  output.bytes = key;
  output.hex = to_hex(key);
  output.binary = to_binary(key);
  output.base64 = to_base64(key);

  return output;
}

} // namespace secure_keygen
