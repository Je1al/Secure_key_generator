#ifndef SECUREKG_DRBG_DRBG_H_
#define SECUREKG_DRBG_DRBG_H_

#include <cstddef>
#include <cstdint>
#include <vector>

namespace securekg::drbg {

using Bytes = std::vector<std::uint8_t>;

// Common interface for the NIST SP 800-90A deterministic random bit generators.
// All three implementations (HMAC-DRBG, Hash-DRBG, CTR-DRBG) follow the same
// instantiate / reseed / generate lifecycle so they are interchangeable behind
// the Csprng facade.
class Drbg {
 public:
  // Per SP 800-90A a DRBG instance must be reseeded before it can be used past
  // its reseed interval. Generate() throws ReseedRequired when that happens; the
  // caller is expected to pull fresh entropy and call reseed().
  class ReseedRequired : public std::exception {
   public:
    const char* what() const noexcept override { return "DRBG reseed required"; }
  };

  virtual ~Drbg() = default;

  // Returns num_bytes of output. additional_input is optional (SP 800-90A
  // "additional input"); pass an empty vector to omit it.
  virtual Bytes generate(std::size_t num_bytes,
                         const Bytes& additional_input = {}) = 0;

  // Mixes fresh entropy back into the state and resets the reseed counter.
  virtual void reseed(const Bytes& entropy,
                      const Bytes& additional_input = {}) = 0;

  virtual const char* name() const = 0;

  // Number of generate() requests served since the last (re)seed.
  virtual std::uint64_t reseed_counter() const = 0;

  // Security strength in bits this mechanism is instantiated at.
  virtual int security_strength() const = 0;
};

}  // namespace securekg::drbg

#endif  // SECUREKG_DRBG_DRBG_H_
