#include "securekg/drbg/hash_drbg.h"

#include <algorithm>

#include "securekg/crypto/sha256.h"
#include "securekg/util/bytes.h"

namespace securekg::drbg {

namespace {

constexpr std::size_t kHashLen = crypto::Sha256::kDigestSize;  // 32

// Hash_df (SP 800-90A 10.3.1): hash-based derivation function producing
// num_bytes of output.
Bytes hash_df(const Bytes& input, std::size_t num_bytes) {
  Bytes out;
  out.reserve(((num_bytes + kHashLen - 1) / kHashLen) * kHashLen);
  std::uint32_t bits = static_cast<std::uint32_t>(num_bytes * 8);
  std::uint8_t bits_be[4] = {
      static_cast<std::uint8_t>((bits >> 24) & 0xFF),
      static_cast<std::uint8_t>((bits >> 16) & 0xFF),
      static_cast<std::uint8_t>((bits >> 8) & 0xFF),
      static_cast<std::uint8_t>(bits & 0xFF)};
  std::uint8_t counter = 0x01;
  while (out.size() < num_bytes) {
    crypto::Sha256 h;
    h.update(&counter, 1);
    h.update(bits_be, 4);
    h.update(input.data(), input.size());
    auto digest = h.finish();
    out.insert(out.end(), digest.begin(), digest.end());
    ++counter;
  }
  out.resize(num_bytes);
  return out;
}

// acc = (acc + addend) mod 2^(8*acc.size()); addend is big-endian, right-aligned.
void add_be(Bytes& acc, const std::uint8_t* addend, std::size_t addend_len) {
  int i = static_cast<int>(acc.size()) - 1;
  int j = static_cast<int>(addend_len) - 1;
  unsigned carry = 0;
  while (i >= 0) {
    unsigned sum = acc[i] + carry + (j >= 0 ? addend[j] : 0);
    acc[i] = static_cast<std::uint8_t>(sum & 0xFF);
    carry = sum >> 8;
    --i;
    --j;
  }
}

void add_u64(Bytes& acc, std::uint64_t value) {
  std::uint8_t be[8];
  for (int i = 0; i < 8; ++i)
    be[i] = static_cast<std::uint8_t>((value >> ((7 - i) * 8)) & 0xFF);
  add_be(acc, be, 8);
}

}  // namespace

HashDrbg::HashDrbg(const Bytes& entropy, const Bytes& nonce,
                   const Bytes& personalization) {
  Bytes seed_material;
  seed_material.insert(seed_material.end(), entropy.begin(), entropy.end());
  seed_material.insert(seed_material.end(), nonce.begin(), nonce.end());
  seed_material.insert(seed_material.end(), personalization.begin(),
                       personalization.end());
  v_ = hash_df(seed_material, kSeedLen);

  Bytes c_input;
  c_input.push_back(0x00);
  c_input.insert(c_input.end(), v_.begin(), v_.end());
  c_ = hash_df(c_input, kSeedLen);

  util::secure_zero(seed_material);
  reseed_counter_ = 1;
}

HashDrbg::~HashDrbg() {
  util::secure_zero(v_);
  util::secure_zero(c_);
}

void HashDrbg::reseed(const Bytes& entropy, const Bytes& additional_input) {
  Bytes seed_material;
  seed_material.push_back(0x01);
  seed_material.insert(seed_material.end(), v_.begin(), v_.end());
  seed_material.insert(seed_material.end(), entropy.begin(), entropy.end());
  seed_material.insert(seed_material.end(), additional_input.begin(),
                       additional_input.end());
  v_ = hash_df(seed_material, kSeedLen);

  Bytes c_input;
  c_input.push_back(0x00);
  c_input.insert(c_input.end(), v_.begin(), v_.end());
  c_ = hash_df(c_input, kSeedLen);

  util::secure_zero(seed_material);
  reseed_counter_ = 1;
}

Bytes HashDrbg::generate(std::size_t num_bytes, const Bytes& additional_input) {
  if (reseed_counter_ > kReseedInterval) throw ReseedRequired();

  // Step 2: fold in additional input.
  if (!additional_input.empty()) {
    crypto::Sha256 h;
    std::uint8_t prefix = 0x02;
    h.update(&prefix, 1);
    h.update(v_.data(), v_.size());
    h.update(additional_input.data(), additional_input.size());
    auto w = h.finish();
    add_be(v_, w.data(), w.size());
  }

  // Step 3: Hashgen.
  Bytes out;
  out.reserve(num_bytes);
  Bytes data = v_;  // working copy
  while (out.size() < num_bytes) {
    auto w = crypto::Sha256::hash(data);
    std::size_t take = std::min(kHashLen, num_bytes - out.size());
    out.insert(out.end(), w.begin(), w.begin() + static_cast<long>(take));
    std::uint8_t one = 0x01;
    add_be(data, &one, 1);  // data = (data + 1) mod 2^seedlen
  }
  util::secure_zero(data);

  // Step 4/5: V = (V + H + C + reseed_counter) mod 2^seedlen.
  {
    crypto::Sha256 h;
    std::uint8_t prefix = 0x03;
    h.update(&prefix, 1);
    h.update(v_.data(), v_.size());
    auto hv = h.finish();
    add_be(v_, hv.data(), hv.size());
  }
  add_be(v_, c_.data(), c_.size());
  add_u64(v_, reseed_counter_);

  ++reseed_counter_;
  return out;
}

}  // namespace securekg::drbg
