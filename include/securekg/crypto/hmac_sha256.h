#ifndef SECUREKG_CRYPTO_HMAC_SHA256_H_
#define SECUREKG_CRYPTO_HMAC_SHA256_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "securekg/crypto/sha256.h"

namespace securekg::crypto {

// HMAC-SHA256 (FIPS 198-1 / RFC 2104) with a streaming interface. The DRBGs
// feed the MAC incrementally, so update() can be called repeatedly between
// reset() and finish().
class HmacSha256 {
 public:
  static constexpr std::size_t kDigestSize = Sha256::kDigestSize;

  HmacSha256(const std::uint8_t* key, std::size_t key_len) {
    reset(key, key_len);
  }

  void reset(const std::uint8_t* key, std::size_t key_len);
  void update(const std::uint8_t* data, std::size_t len) {
    inner_.update(data, len);
  }
  void update(const std::vector<std::uint8_t>& data) {
    inner_.update(data.data(), data.size());
  }
  void finish(std::uint8_t out[kDigestSize]);
  std::array<std::uint8_t, kDigestSize> finish();

  static std::array<std::uint8_t, kDigestSize> mac(const std::uint8_t* key,
                                                   std::size_t key_len,
                                                   const std::uint8_t* data,
                                                   std::size_t data_len);
  static std::array<std::uint8_t, kDigestSize> mac(
      const std::vector<std::uint8_t>& key,
      const std::vector<std::uint8_t>& data) {
    return mac(key.data(), key.size(), data.data(), data.size());
  }

 private:
  Sha256 inner_;
  std::uint8_t o_key_pad_[Sha256::kBlockSize];
};

}  // namespace securekg::crypto

#endif  // SECUREKG_CRYPTO_HMAC_SHA256_H_
