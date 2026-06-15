#include "securekg/crypto/kdf.h"

#include <algorithm>
#include <stdexcept>

#include "securekg/crypto/hmac_sha256.h"
#include "securekg/crypto/sha256.h"

namespace securekg::crypto {

namespace {
constexpr std::size_t kHashLen = Sha256::kDigestSize;
}

Bytes hkdf_extract(const Bytes& salt, const Bytes& ikm) {
  Bytes effective_salt = salt;
  if (effective_salt.empty()) effective_salt.assign(kHashLen, 0x00);
  auto prk = HmacSha256::mac(effective_salt, ikm);
  return Bytes(prk.begin(), prk.end());
}

Bytes hkdf_expand(const Bytes& prk, const Bytes& info, std::size_t length) {
  if (length > 255 * kHashLen)
    throw std::invalid_argument("hkdf_expand: length too large");

  Bytes okm;
  okm.reserve(length);
  Bytes t;  // T(0) is empty
  std::uint8_t counter = 1;
  while (okm.size() < length) {
    HmacSha256 mac(prk.data(), prk.size());
    mac.update(t.data(), t.size());
    mac.update(info.data(), info.size());
    mac.update(&counter, 1);
    auto block = mac.finish();
    t.assign(block.begin(), block.end());
    std::size_t take = std::min(kHashLen, length - okm.size());
    okm.insert(okm.end(), t.begin(), t.begin() + static_cast<long>(take));
    ++counter;
  }
  return okm;
}

Bytes hkdf(const Bytes& salt, const Bytes& ikm, const Bytes& info,
           std::size_t length) {
  return hkdf_expand(hkdf_extract(salt, ikm), info, length);
}

Bytes pbkdf2_hmac_sha256(const Bytes& password, const Bytes& salt,
                         std::uint32_t iterations, std::size_t dk_len) {
  if (iterations < 1)
    throw std::invalid_argument("pbkdf2: iterations must be >= 1");

  Bytes dk;
  dk.reserve(dk_len);
  std::uint32_t block_index = 1;
  while (dk.size() < dk_len) {
    // U1 = HMAC(password, salt || INT_BE32(block_index))
    std::uint8_t idx_be[4] = {
        static_cast<std::uint8_t>((block_index >> 24) & 0xFF),
        static_cast<std::uint8_t>((block_index >> 16) & 0xFF),
        static_cast<std::uint8_t>((block_index >> 8) & 0xFF),
        static_cast<std::uint8_t>(block_index & 0xFF)};
    HmacSha256 first(password.data(), password.size());
    first.update(salt.data(), salt.size());
    first.update(idx_be, 4);
    auto u = first.finish();

    std::array<std::uint8_t, kHashLen> t = u;
    for (std::uint32_t i = 1; i < iterations; ++i) {
      u = HmacSha256::mac(password.data(), password.size(), u.data(), u.size());
      for (std::size_t j = 0; j < kHashLen; ++j) t[j] ^= u[j];
    }

    std::size_t take = std::min(kHashLen, dk_len - dk.size());
    dk.insert(dk.end(), t.begin(), t.begin() + static_cast<long>(take));
    ++block_index;
  }
  return dk;
}

}  // namespace securekg::crypto
