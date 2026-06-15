#ifndef SECUREKG_DRBG_HMAC_DRBG_H_
#define SECUREKG_DRBG_HMAC_DRBG_H_

#include <array>

#include "securekg/crypto/sha256.h"
#include "securekg/drbg/drbg.h"

namespace securekg::drbg {

// HMAC-DRBG using HMAC-SHA256 (NIST SP 800-90A, Section 10.1.2).
// Provides a 256-bit security strength. Reseed interval is 2^48 requests.
class HmacDrbg : public Drbg {
 public:
  static constexpr std::uint64_t kReseedInterval = (std::uint64_t(1) << 48);

  HmacDrbg(const Bytes& entropy, const Bytes& nonce,
           const Bytes& personalization = {});
  ~HmacDrbg() override;

  Bytes generate(std::size_t num_bytes,
                 const Bytes& additional_input = {}) override;
  void reseed(const Bytes& entropy,
              const Bytes& additional_input = {}) override;

  const char* name() const override { return "HMAC-DRBG(SHA-256)"; }
  std::uint64_t reseed_counter() const override { return reseed_counter_; }
  int security_strength() const override { return 256; }

 private:
  // The SP 800-90A "Update" function. provided_data may be empty.
  void update(const Bytes& provided_data);

  std::array<std::uint8_t, crypto::Sha256::kDigestSize> k_;
  std::array<std::uint8_t, crypto::Sha256::kDigestSize> v_;
  std::uint64_t reseed_counter_;
};

}  // namespace securekg::drbg

#endif  // SECUREKG_DRBG_HMAC_DRBG_H_
