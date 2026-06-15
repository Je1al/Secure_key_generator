#include "securekg/crypto/hmac_sha256.h"

#include <cstring>

namespace securekg::crypto {

void HmacSha256::reset(const std::uint8_t* key, std::size_t key_len) {
  std::uint8_t k0[Sha256::kBlockSize];
  std::memset(k0, 0, sizeof(k0));

  if (key_len > Sha256::kBlockSize) {
    // Keys longer than the block size are hashed down first (RFC 2104).
    std::array<std::uint8_t, Sha256::kDigestSize> hk =
        Sha256::hash(key, key_len);
    std::memcpy(k0, hk.data(), hk.size());
  } else {
    std::memcpy(k0, key, key_len);
  }

  std::uint8_t i_key_pad[Sha256::kBlockSize];
  for (std::size_t i = 0; i < Sha256::kBlockSize; ++i) {
    i_key_pad[i] = static_cast<std::uint8_t>(k0[i] ^ 0x36);
    o_key_pad_[i] = static_cast<std::uint8_t>(k0[i] ^ 0x5c);
  }

  inner_.reset();
  inner_.update(i_key_pad, Sha256::kBlockSize);

  // Do not leave the raw key bytes on the stack.
  volatile std::uint8_t* z = k0;
  for (std::size_t i = 0; i < sizeof(k0); ++i) z[i] = 0;
  volatile std::uint8_t* zi = i_key_pad;
  for (std::size_t i = 0; i < sizeof(i_key_pad); ++i) zi[i] = 0;
}

void HmacSha256::finish(std::uint8_t out[kDigestSize]) {
  std::uint8_t inner_digest[Sha256::kDigestSize];
  inner_.finish(inner_digest);

  Sha256 outer;
  outer.update(o_key_pad_, Sha256::kBlockSize);
  outer.update(inner_digest, Sha256::kDigestSize);
  outer.finish(out);
}

std::array<std::uint8_t, HmacSha256::kDigestSize> HmacSha256::finish() {
  std::array<std::uint8_t, kDigestSize> out{};
  finish(out.data());
  return out;
}

std::array<std::uint8_t, HmacSha256::kDigestSize> HmacSha256::mac(
    const std::uint8_t* key, std::size_t key_len, const std::uint8_t* data,
    std::size_t data_len) {
  HmacSha256 h(key, key_len);
  h.update(data, data_len);
  return h.finish();
}

}  // namespace securekg::crypto
