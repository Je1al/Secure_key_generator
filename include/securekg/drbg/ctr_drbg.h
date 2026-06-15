#ifndef SECUREKG_DRBG_CTR_DRBG_H_
#define SECUREKG_DRBG_CTR_DRBG_H_

#include "securekg/drbg/drbg.h"

namespace securekg::drbg {

// CTR-DRBG using AES-256 without a derivation function
// (NIST SP 800-90A, Section 10.2.1).
//
// "Without df" means the seed material must be supplied at full entropy:
//   keylen + blocklen = 32 + 16 = 48 bytes (seedlen).
// The entropy input to the constructor and reseed() must therefore be exactly
// kSeedLen bytes. Personalization / additional input are zero-padded (or
// truncated) to kSeedLen. 256-bit security strength.
class CtrDrbg : public Drbg {
 public:
  static constexpr std::size_t kKeyLen = 32;    // AES-256
  static constexpr std::size_t kBlockLen = 16;
  static constexpr std::size_t kSeedLen = kKeyLen + kBlockLen;  // 48
  static constexpr std::uint64_t kReseedInterval = (std::uint64_t(1) << 48);

  CtrDrbg(const Bytes& entropy, const Bytes& personalization = {});
  ~CtrDrbg() override;

  Bytes generate(std::size_t num_bytes,
                 const Bytes& additional_input = {}) override;
  void reseed(const Bytes& entropy,
              const Bytes& additional_input = {}) override;

  const char* name() const override { return "CTR-DRBG(AES-256, no df)"; }
  std::uint64_t reseed_counter() const override { return reseed_counter_; }
  int security_strength() const override { return 256; }

 private:
  void update(const Bytes& provided_data);  // provided_data is kSeedLen bytes
  void increment_v();

  Bytes key_;  // kKeyLen bytes
  Bytes v_;    // kBlockLen bytes (counter)
  std::uint64_t reseed_counter_;
};

}  // namespace securekg::drbg

#endif  // SECUREKG_DRBG_CTR_DRBG_H_
