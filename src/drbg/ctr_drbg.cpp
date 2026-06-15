#include "securekg/drbg/ctr_drbg.h"

#include <algorithm>
#include <stdexcept>

#include "securekg/crypto/aes.h"
#include "securekg/util/bytes.h"

namespace securekg::drbg {

namespace {

// Returns data padded with trailing zeros (or truncated) to exactly len bytes.
Bytes pad_to(const Bytes& data, std::size_t len) {
  Bytes out(len, 0x00);
  std::size_t take = std::min(data.size(), len);
  std::copy(data.begin(), data.begin() + static_cast<long>(take), out.begin());
  return out;
}

}  // namespace

void CtrDrbg::increment_v() {
  for (int i = static_cast<int>(kBlockLen) - 1; i >= 0; --i)
    if (++v_[i] != 0) break;
}

// CTR_DRBG_Update (SP 800-90A 10.2.1.2).
void CtrDrbg::update(const Bytes& provided_data) {
  Bytes temp;
  temp.reserve(kSeedLen + kBlockLen);
  crypto::Aes aes(key_.data(), key_.size());
  while (temp.size() < kSeedLen) {
    increment_v();
    std::uint8_t block[kBlockLen];
    aes.encrypt_block(v_.data(), block);
    temp.insert(temp.end(), block, block + kBlockLen);
  }
  temp.resize(kSeedLen);
  for (std::size_t i = 0; i < kSeedLen; ++i) temp[i] ^= provided_data[i];

  std::copy(temp.begin(), temp.begin() + kKeyLen, key_.begin());
  std::copy(temp.begin() + kKeyLen, temp.end(), v_.begin());
  util::secure_zero(temp);
}

CtrDrbg::CtrDrbg(const Bytes& entropy, const Bytes& personalization) {
  if (entropy.size() != kSeedLen)
    throw std::invalid_argument(
        "CtrDrbg: entropy must be exactly 48 bytes (no-df mode)");

  key_.assign(kKeyLen, 0x00);
  v_.assign(kBlockLen, 0x00);

  Bytes perso = pad_to(personalization, kSeedLen);
  Bytes seed_material(kSeedLen);
  for (std::size_t i = 0; i < kSeedLen; ++i)
    seed_material[i] = entropy[i] ^ perso[i];
  update(seed_material);
  util::secure_zero(seed_material);
  reseed_counter_ = 1;
}

CtrDrbg::~CtrDrbg() {
  util::secure_zero(key_);
  util::secure_zero(v_);
}

void CtrDrbg::reseed(const Bytes& entropy, const Bytes& additional_input) {
  if (entropy.size() != kSeedLen)
    throw std::invalid_argument(
        "CtrDrbg: reseed entropy must be exactly 48 bytes (no-df mode)");
  Bytes add = pad_to(additional_input, kSeedLen);
  Bytes seed_material(kSeedLen);
  for (std::size_t i = 0; i < kSeedLen; ++i)
    seed_material[i] = entropy[i] ^ add[i];
  update(seed_material);
  util::secure_zero(seed_material);
  reseed_counter_ = 1;
}

Bytes CtrDrbg::generate(std::size_t num_bytes, const Bytes& additional_input) {
  if (reseed_counter_ > kReseedInterval) throw ReseedRequired();

  Bytes add = pad_to(additional_input, kSeedLen);  // all zero if none supplied
  if (!additional_input.empty()) update(add);

  Bytes out;
  out.reserve(num_bytes);
  crypto::Aes aes(key_.data(), key_.size());
  while (out.size() < num_bytes) {
    increment_v();
    std::uint8_t block[kBlockLen];
    aes.encrypt_block(v_.data(), block);
    std::size_t take = std::min(kBlockLen, num_bytes - out.size());
    out.insert(out.end(), block, block + take);
  }

  update(add);
  ++reseed_counter_;
  return out;
}

}  // namespace securekg::drbg
