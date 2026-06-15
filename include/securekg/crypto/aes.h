#ifndef SECUREKG_CRYPTO_AES_H_
#define SECUREKG_CRYPTO_AES_H_

#include <cstddef>
#include <cstdint>

namespace securekg::crypto {

// AES block cipher (FIPS 197), encryption direction only. That is all the
// CTR_DRBG and CTR keystream below require, so the (unused) inverse cipher is
// intentionally omitted. Supports 128/192/256-bit keys.
class Aes {
 public:
  static constexpr std::size_t kBlockSize = 16;

  // key_len must be 16, 24 or 32 bytes; throws std::invalid_argument otherwise.
  Aes(const std::uint8_t* key, std::size_t key_len);
  ~Aes();

  void encrypt_block(const std::uint8_t in[kBlockSize],
                     std::uint8_t out[kBlockSize]) const;

  // CTR mode (SP 800-38A): XORs len bytes of keystream into out. counter is a
  // 16-byte big-endian block, incremented (mod 2^128) after each block and left
  // updated on return so calls can be chained.
  void ctr_xor(const std::uint8_t* in, std::uint8_t* out, std::size_t len,
               std::uint8_t counter[kBlockSize]) const;

  int rounds() const { return rounds_; }

 private:
  int rounds_;
  std::uint8_t round_keys_[16 * 15];  // up to 16*(14+1) bytes for AES-256
};

}  // namespace securekg::crypto

#endif  // SECUREKG_CRYPTO_AES_H_
