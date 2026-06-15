// libFuzzer harness for the encoders/decoders. Decoders must never crash on
// hostile input (they reject by throwing), and encode->decode must round-trip.
//
// Build (clang):
//   clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -Iinclude \
//     fuzz/fuzz_encoding.cpp src/**/*.cpp -o fuzz_encoding
#include <cstdint>
#include <string>
#include <vector>

#include "securekg/util/bytes.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace securekg::util;
  std::vector<std::uint8_t> bytes(data, data + size);

  // Encoders always succeed; the resulting text must decode back exactly.
  if (from_hex(to_hex(bytes)) != bytes) __builtin_trap();
  if (from_base64(to_base64(bytes)) != bytes) __builtin_trap();

  // Decoders must reject malformed input cleanly (by exception), never crash.
  std::string text(reinterpret_cast<const char*>(data), size);
  try {
    from_hex(text);
  } catch (const std::exception&) {
  }
  try {
    from_base64(text);
  } catch (const std::exception&) {
  }
  return 0;
}
