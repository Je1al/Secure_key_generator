#ifndef SECUREKG_CRYPTO_KDF_H_
#define SECUREKG_CRYPTO_KDF_H_

#include <cstddef>
#include <cstdint>
#include <vector>

namespace securekg::crypto {

using Bytes = std::vector<std::uint8_t>;

// HKDF-SHA256 (RFC 5869).
// Extract: PRK = HMAC-SHA256(salt, IKM). An empty salt is treated as a string
// of HashLen zero bytes, as required by the RFC.
Bytes hkdf_extract(const Bytes& salt, const Bytes& ikm);
// Expand: OKM = T(1) | T(2) | ... truncated to length bytes (length <= 255*32).
Bytes hkdf_expand(const Bytes& prk, const Bytes& info, std::size_t length);
// Convenience: extract-then-expand in one call.
Bytes hkdf(const Bytes& salt, const Bytes& ikm, const Bytes& info,
           std::size_t length);

// PBKDF2-HMAC-SHA256 (RFC 8018). iterations must be >= 1.
Bytes pbkdf2_hmac_sha256(const Bytes& password, const Bytes& salt,
                         std::uint32_t iterations, std::size_t dk_len);

}  // namespace securekg::crypto

#endif  // SECUREKG_CRYPTO_KDF_H_
