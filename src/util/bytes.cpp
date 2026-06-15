#include "securekg/util/bytes.h"

#include <cctype>
#include <stdexcept>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace securekg::util {
namespace {

constexpr char kHex[] = "0123456789abcdef";
constexpr char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

std::string to_hex(const std::uint8_t* data, std::size_t len) {
  std::string out;
  out.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(kHex[(data[i] >> 4) & 0x0F]);
    out.push_back(kHex[data[i] & 0x0F]);
  }
  return out;
}

std::string to_hex(const Bytes& data) { return to_hex(data.data(), data.size()); }

Bytes from_hex(const std::string& hex) {
  Bytes nibbles;
  nibbles.reserve(hex.size());
  for (char c : hex) {
    if (std::isspace(static_cast<unsigned char>(c))) continue;
    int v = hex_value(c);
    if (v < 0) throw std::invalid_argument("from_hex: non-hex character");
    nibbles.push_back(static_cast<std::uint8_t>(v));
  }
  if (nibbles.size() % 2 != 0)
    throw std::invalid_argument("from_hex: odd number of hex digits");
  Bytes out;
  out.reserve(nibbles.size() / 2);
  for (std::size_t i = 0; i < nibbles.size(); i += 2)
    out.push_back(static_cast<std::uint8_t>((nibbles[i] << 4) | nibbles[i + 1]));
  return out;
}

std::string to_base64(const Bytes& data) {
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  std::size_t i = 0;
  while (i + 2 < data.size()) {
    std::uint32_t t = (std::uint32_t(data[i]) << 16) |
                      (std::uint32_t(data[i + 1]) << 8) | data[i + 2];
    out.push_back(kB64[(t >> 18) & 0x3F]);
    out.push_back(kB64[(t >> 12) & 0x3F]);
    out.push_back(kB64[(t >> 6) & 0x3F]);
    out.push_back(kB64[t & 0x3F]);
    i += 3;
  }
  if (i < data.size()) {
    std::uint32_t t = std::uint32_t(data[i]) << 16;
    out.push_back(kB64[(t >> 18) & 0x3F]);
    if (i + 1 < data.size()) {
      t |= std::uint32_t(data[i + 1]) << 8;
      out.push_back(kB64[(t >> 12) & 0x3F]);
      out.push_back(kB64[(t >> 6) & 0x3F]);
      out.push_back('=');
    } else {
      out.push_back(kB64[(t >> 12) & 0x3F]);
      out.push_back('=');
      out.push_back('=');
    }
  }
  return out;
}

Bytes from_base64(const std::string& b64) {
  auto decode = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  Bytes out;
  std::uint32_t buffer = 0;
  int bits = 0;
  for (char c : b64) {
    if (c == '=' || std::isspace(static_cast<unsigned char>(c))) continue;
    int v = decode(c);
    if (v < 0) throw std::invalid_argument("from_base64: invalid character");
    buffer = (buffer << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xFF));
    }
  }
  return out;
}

std::string to_binary(const Bytes& data) {
  std::string out;
  out.reserve(data.size() * 8);
  for (std::uint8_t byte : data)
    for (int bit = 7; bit >= 0; --bit)
      out.push_back(((byte >> bit) & 1) ? '1' : '0');
  return out;
}

std::string to_c_array(const Bytes& data, const std::string& name) {
  std::string out = "static const unsigned char " + name + "[" +
                    std::to_string(data.size()) + "] = {\n";
  for (std::size_t i = 0; i < data.size(); ++i) {
    if (i % 12 == 0) out += "    ";
    out += "0x";
    out.push_back(kHex[(data[i] >> 4) & 0x0F]);
    out.push_back(kHex[data[i] & 0x0F]);
    out += ",";
    out += ((i % 12 == 11) || i + 1 == data.size()) ? "\n" : " ";
  }
  out += "};\n";
  return out;
}

bool ct_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t len) {
  volatile std::uint8_t diff = 0;
  for (std::size_t i = 0; i < len; ++i) diff |= a[i] ^ b[i];
  return diff == 0;
}

bool ct_equal(const Bytes& a, const Bytes& b) {
  if (a.size() != b.size()) return false;
  return ct_equal(a.data(), b.data(), a.size());
}

void secure_zero(void* ptr, std::size_t len) {
#if defined(_WIN32)
  SecureZeroMemory(ptr, len);
#else
  volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
  while (len--) *p++ = 0;
#endif
}

void secure_zero(Bytes& buf) {
  if (!buf.empty()) secure_zero(buf.data(), buf.size());
}

}  // namespace securekg::util
