#ifndef SECUREKG_KEYGEN_CSPRNG_H_
#define SECUREKG_KEYGEN_CSPRNG_H_

#include <memory>
#include <string>

#include "securekg/drbg/drbg.h"

namespace securekg::keygen {

using Bytes = std::vector<std::uint8_t>;

enum class DrbgKind { HmacSha256, HashSha256, CtrAes256 };

const char* to_string(DrbgKind kind);
bool parse_drbg_kind(const std::string& s, DrbgKind& out);

// A seeded, self-reseeding cryptographically secure pseudorandom number
// generator. It wraps one of the SP 800-90A DRBGs, seeds it from the OS entropy
// source (os_random), and transparently reseeds when the DRBG reaches its
// reseed interval. Large requests are split to respect the per-request output
// limit of SP 800-90A (2^19 bits).
class Csprng {
 public:
  explicit Csprng(DrbgKind kind = DrbgKind::HmacSha256,
                  const Bytes& personalization = {});

  // Deterministic construction from explicit seed material -- used by the test
  // vectors and by anyone who needs reproducible output. nonce is ignored for
  // CTR-DRBG (no-df), whose entropy must be exactly 48 bytes.
  static Csprng from_seed(DrbgKind kind, const Bytes& entropy,
                          const Bytes& nonce, const Bytes& personalization = {});

  Bytes random_bytes(std::size_t n);
  void reseed_from_os();

  const char* drbg_name() const { return drbg_->name(); }
  int security_strength() const { return drbg_->security_strength(); }
  DrbgKind kind() const { return kind_; }

 private:
  Csprng(DrbgKind kind, std::unique_ptr<drbg::Drbg> d) : kind_(kind), drbg_(std::move(d)) {}

  static constexpr std::size_t kMaxPerRequest = 65536;  // 2^19 bits

  DrbgKind kind_;
  std::unique_ptr<drbg::Drbg> drbg_;
};

}  // namespace securekg::keygen

#endif  // SECUREKG_KEYGEN_CSPRNG_H_
