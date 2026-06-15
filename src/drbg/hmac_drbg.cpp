#include "securekg/drbg/hmac_drbg.h"

#include <algorithm>

#include "securekg/crypto/hmac_sha256.h"
#include "securekg/util/bytes.h"

namespace securekg::drbg {

namespace {
constexpr std::size_t kOut = crypto::Sha256::kDigestSize;
}

void HmacDrbg::update(const Bytes& provided_data) {
  // K = HMAC(K, V || 0x00 || provided_data); V = HMAC(K, V)
  {
    crypto::HmacSha256 mac(k_.data(), k_.size());
    mac.update(v_.data(), v_.size());
    std::uint8_t sep = 0x00;
    mac.update(&sep, 1);
    mac.update(provided_data.data(), provided_data.size());
    mac.finish(k_.data());
  }
  v_ = crypto::HmacSha256::mac(k_.data(), k_.size(), v_.data(), v_.size());

  if (provided_data.empty()) return;

  // K = HMAC(K, V || 0x01 || provided_data); V = HMAC(K, V)
  {
    crypto::HmacSha256 mac(k_.data(), k_.size());
    mac.update(v_.data(), v_.size());
    std::uint8_t sep = 0x01;
    mac.update(&sep, 1);
    mac.update(provided_data.data(), provided_data.size());
    mac.finish(k_.data());
  }
  v_ = crypto::HmacSha256::mac(k_.data(), k_.size(), v_.data(), v_.size());
}

HmacDrbg::HmacDrbg(const Bytes& entropy, const Bytes& nonce,
                   const Bytes& personalization) {
  k_.fill(0x00);
  v_.fill(0x01);
  Bytes seed_material;
  seed_material.reserve(entropy.size() + nonce.size() + personalization.size());
  seed_material.insert(seed_material.end(), entropy.begin(), entropy.end());
  seed_material.insert(seed_material.end(), nonce.begin(), nonce.end());
  seed_material.insert(seed_material.end(), personalization.begin(),
                       personalization.end());
  update(seed_material);
  util::secure_zero(seed_material);
  reseed_counter_ = 1;
}

HmacDrbg::~HmacDrbg() {
  util::secure_zero(k_.data(), k_.size());
  util::secure_zero(v_.data(), v_.size());
}

void HmacDrbg::reseed(const Bytes& entropy, const Bytes& additional_input) {
  Bytes seed_material;
  seed_material.reserve(entropy.size() + additional_input.size());
  seed_material.insert(seed_material.end(), entropy.begin(), entropy.end());
  seed_material.insert(seed_material.end(), additional_input.begin(),
                       additional_input.end());
  update(seed_material);
  util::secure_zero(seed_material);
  reseed_counter_ = 1;
}

Bytes HmacDrbg::generate(std::size_t num_bytes, const Bytes& additional_input) {
  if (reseed_counter_ > kReseedInterval) throw ReseedRequired();

  if (!additional_input.empty()) update(additional_input);

  Bytes out;
  out.reserve(num_bytes);
  while (out.size() < num_bytes) {
    v_ = crypto::HmacSha256::mac(k_.data(), k_.size(), v_.data(), v_.size());
    std::size_t take = std::min(kOut, num_bytes - out.size());
    out.insert(out.end(), v_.begin(), v_.begin() + static_cast<long>(take));
  }

  update(additional_input);
  ++reseed_counter_;
  return out;
}

}  // namespace securekg::drbg
