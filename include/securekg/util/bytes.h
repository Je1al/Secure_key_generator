#ifndef SECUREKG_UTIL_BYTES_H_
#define SECUREKG_UTIL_BYTES_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace securekg::util {

using Bytes = std::vector<std::uint8_t>;

// --- Encoding helpers -------------------------------------------------------
std::string to_hex(const std::uint8_t* data, std::size_t len);
std::string to_hex(const Bytes& data);
// Parses a hex string (whitespace ignored). Throws std::invalid_argument on
// odd length or non-hex characters.
Bytes from_hex(const std::string& hex);

std::string to_base64(const Bytes& data);
Bytes from_base64(const std::string& b64);

std::string to_binary(const Bytes& data);
std::string to_c_array(const Bytes& data, const std::string& name);

// --- Security helpers -------------------------------------------------------
// Constant-time equality. Returns false immediately on length mismatch, but
// for equal lengths the running time does not depend on the contents.
bool ct_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t len);
bool ct_equal(const Bytes& a, const Bytes& b);

// Best-effort memory wipe the optimizer is not allowed to elide. Used to clear
// key material and DRBG state as soon as it is no longer needed.
void secure_zero(void* ptr, std::size_t len);
void secure_zero(Bytes& buf);

}  // namespace securekg::util

#endif  // SECUREKG_UTIL_BYTES_H_
