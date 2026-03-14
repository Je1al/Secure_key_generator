#ifndef SECURE_KEYGEN_KEYGEN_H
#define SECURE_KEYGEN_KEYGEN_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace secure_keygen {

struct KeyOutput {
  std::vector<uint8_t> bytes;
  std::string hex;
  std::string binary;
  std::string base64;
};

class KeyGenerator {
public:
  enum class KeySizeBits : std::size_t {
    Bits128 = 128,
    Bits256 = 256,
    Bits512 = 512
  };

  KeyOutput generate(KeySizeBits size_bits) const;
};

} // namespace secure_keygen

#endif // SECURE_KEYGEN_KEYGEN_H
