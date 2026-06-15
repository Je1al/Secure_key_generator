#ifndef SECUREKG_DRBG_HASH_DRBG_H_
#define SECUREKG_DRBG_HASH_DRBG_H_

#include "securekg/drbg/drbg.h"

namespace securekg::drbg {

// Hash-DRBG using SHA-256 (NIST SP 800-90A, Section 10.1.1).
// seedlen = 440 bits (55 bytes); 256-bit security strength.
class HashDrbg : public Drbg {
 public:
  static constexpr std::size_t kSeedLen = 55;          // 440 bits
  static constexpr std::uint64_t kReseedInterval = (std::uint64_t(1) << 48);

  HashDrbg(const Bytes& entropy, const Bytes& nonce,
           const Bytes& personalization = {});
  ~HashDrbg() override;

  Bytes generate(std::size_t num_bytes,
                 const Bytes& additional_input = {}) override;
  void reseed(const Bytes& entropy,
              const Bytes& additional_input = {}) override;

  const char* name() const override { return "Hash-DRBG(SHA-256)"; }
  std::uint64_t reseed_counter() const override { return reseed_counter_; }
  int security_strength() const override { return 256; }

 private:
  Bytes v_;  // kSeedLen bytes
  Bytes c_;  // kSeedLen bytes
  std::uint64_t reseed_counter_;
};

}  // namespace securekg::drbg

#endif  // SECUREKG_DRBG_HASH_DRBG_H_
