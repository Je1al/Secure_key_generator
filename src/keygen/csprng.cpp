#include "securekg/keygen/csprng.h"

#include <algorithm>
#include <stdexcept>

#include "securekg/drbg/ctr_drbg.h"
#include "securekg/drbg/hash_drbg.h"
#include "securekg/drbg/hmac_drbg.h"
#include "securekg/entropy/os_entropy.h"

namespace securekg::keygen {

const char* to_string(DrbgKind kind) {
  switch (kind) {
    case DrbgKind::HmacSha256: return "hmac-sha256";
    case DrbgKind::HashSha256: return "hash-sha256";
    case DrbgKind::CtrAes256: return "ctr-aes256";
  }
  return "unknown";
}

bool parse_drbg_kind(const std::string& s, DrbgKind& out) {
  if (s == "hmac" || s == "hmac-sha256" || s == "hmac-drbg") {
    out = DrbgKind::HmacSha256;
    return true;
  }
  if (s == "hash" || s == "hash-sha256" || s == "hash-drbg") {
    out = DrbgKind::HashSha256;
    return true;
  }
  if (s == "ctr" || s == "ctr-aes256" || s == "ctr-drbg") {
    out = DrbgKind::CtrAes256;
    return true;
  }
  return false;
}

namespace {

// Entropy size (bytes) to draw for (re)seeding each mechanism. HMAC/Hash-DRBG
// are seeded at their 256-bit strength; CTR-DRBG (no df) requires exactly
// keylen+blocklen = 48 bytes.
std::size_t entropy_len(DrbgKind kind) {
  return kind == DrbgKind::CtrAes256 ? std::size_t(48) : std::size_t(32);
}

std::unique_ptr<drbg::Drbg> make_drbg(DrbgKind kind, const Bytes& entropy,
                                      const Bytes& nonce, const Bytes& perso) {
  switch (kind) {
    case DrbgKind::HmacSha256:
      return std::make_unique<drbg::HmacDrbg>(entropy, nonce, perso);
    case DrbgKind::HashSha256:
      return std::make_unique<drbg::HashDrbg>(entropy, nonce, perso);
    case DrbgKind::CtrAes256:
      return std::make_unique<drbg::CtrDrbg>(entropy, perso);
  }
  throw std::invalid_argument("make_drbg: unknown DRBG kind");
}

}  // namespace

Csprng::Csprng(DrbgKind kind, const Bytes& personalization) : kind_(kind) {
  Bytes entropy = entropy::os_random(entropy_len(kind));
  // A fresh nonce strengthens instantiation (SP 800-90A 8.6.7); unused by CTR.
  Bytes nonce = kind == DrbgKind::CtrAes256 ? Bytes{} : entropy::os_random(16);
  drbg_ = make_drbg(kind, entropy, nonce, personalization);
}

Csprng Csprng::from_seed(DrbgKind kind, const Bytes& entropy,
                         const Bytes& nonce, const Bytes& personalization) {
  return Csprng(kind, make_drbg(kind, entropy, nonce, personalization));
}

void Csprng::reseed_from_os() {
  Bytes entropy = entropy::os_random(entropy_len(kind_));
  drbg_->reseed(entropy);
}

Bytes Csprng::random_bytes(std::size_t n) {
  Bytes out;
  out.reserve(n);
  while (out.size() < n) {
    std::size_t want = std::min(kMaxPerRequest, n - out.size());
    Bytes chunk;
    try {
      chunk = drbg_->generate(want);
    } catch (const drbg::Drbg::ReseedRequired&) {
      reseed_from_os();
      chunk = drbg_->generate(want);
    }
    out.insert(out.end(), chunk.begin(), chunk.end());
  }
  return out;
}

}  // namespace securekg::keygen
