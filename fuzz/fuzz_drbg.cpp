// libFuzzer harness for the DRBGs. Treats the input as seed material, derives
// valid-length entropy/nonce/personalization for each mechanism, and exercises
// instantiate -> generate -> reseed, asserting no crash / sanitizer finding.
//
// Build (clang):
//   clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -Iinclude \
//     fuzz/fuzz_drbg.cpp src/**/*.cpp -o fuzz_drbg
#include <cstdint>
#include <vector>

#include "securekg/crypto/sha256.h"
#include "securekg/drbg/ctr_drbg.h"
#include "securekg/drbg/hash_drbg.h"
#include "securekg/drbg/hmac_drbg.h"

namespace {

using Bytes = std::vector<std::uint8_t>;

// Deterministically expand arbitrary input to exactly len bytes via SHA-256 in
// counter mode, so every fuzz input maps to a valid seed of the required size.
Bytes expand(const std::uint8_t* data, std::size_t size, std::size_t len) {
  Bytes out;
  std::uint32_t counter = 0;
  while (out.size() < len) {
    securekg::crypto::Sha256 h;
    h.update(reinterpret_cast<const std::uint8_t*>(&counter), sizeof(counter));
    h.update(data, size);
    auto d = h.finish();
    out.insert(out.end(), d.begin(), d.end());
    ++counter;
  }
  out.resize(len);
  return out;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  // Request length and additional-input choices are taken from the input.
  std::size_t req = size == 0 ? 1 : (data[0] % 200) + 1;
  Bytes addin = expand(data, size, (size % 40));

  {
    Bytes e = expand(data, size, 32);
    Bytes n = expand(data, size, 16);
    securekg::drbg::HmacDrbg d(e, n, addin);
    d.generate(req, addin);
    d.reseed(expand(data, size, 32));
    d.generate(req);
  }
  {
    Bytes e = expand(data, size, 32);
    Bytes n = expand(data, size, 16);
    securekg::drbg::HashDrbg d(e, n);
    d.generate(req, addin);
    d.reseed(expand(data, size, 32), addin);
    d.generate(req);
  }
  {
    Bytes e = expand(data, size, 48);  // CTR no-df requires exactly 48 bytes
    securekg::drbg::CtrDrbg d(e, addin);
    d.generate(req, addin);
    d.reseed(expand(data, size, 48));
    d.generate(req);
  }
  return 0;
}
