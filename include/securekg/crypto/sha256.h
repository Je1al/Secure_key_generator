#ifndef SECUREKG_CRYPTO_SHA256_H_
#define SECUREKG_CRYPTO_SHA256_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace securekg::crypto {

// SHA-256 (FIPS 180-4) implemented from scratch with a streaming interface so
// it can hash arbitrarily long inputs and back HMAC / HKDF / the DRBGs without
// buffering the whole message in memory.
class Sha256 {
 public:
  static constexpr std::size_t kDigestSize = 32;
  static constexpr std::size_t kBlockSize = 64;

  Sha256() { reset(); }

  void reset();
  void update(const std::uint8_t* data, std::size_t len);
  void update(const std::vector<std::uint8_t>& data) {
    update(data.data(), data.size());
  }
  // Finalizes into a 32-byte digest. The object must be reset() before reuse.
  void finish(std::uint8_t out[kDigestSize]);
  std::array<std::uint8_t, kDigestSize> finish();

  // One-shot convenience wrappers.
  static std::array<std::uint8_t, kDigestSize> hash(const std::uint8_t* data,
                                                    std::size_t len);
  static std::array<std::uint8_t, kDigestSize> hash(
      const std::vector<std::uint8_t>& data) {
    return hash(data.data(), data.size());
  }

 private:
  void process(const std::uint8_t block[kBlockSize]);

  std::uint32_t h_[8];
  std::uint8_t buffer_[kBlockSize];
  std::size_t buffer_len_;
  std::uint64_t total_len_;
};

}  // namespace securekg::crypto

#endif  // SECUREKG_CRYPTO_SHA256_H_
