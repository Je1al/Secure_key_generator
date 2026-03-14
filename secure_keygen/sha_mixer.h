#ifndef SECURE_KEYGEN_SHA_MIXER_H
#define SECURE_KEYGEN_SHA_MIXER_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace secure_keygen {

class ShaMixer {
public:
  // Mixes entropy through multiple rounds of SHA-256 to produce output bytes.
  std::vector<uint8_t> mix(const std::vector<uint8_t>& entropy,
                           std::size_t out_len,
                           std::size_t rounds = 3) const;

  static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
};

} // namespace secure_keygen

#endif // SECURE_KEYGEN_SHA_MIXER_H
