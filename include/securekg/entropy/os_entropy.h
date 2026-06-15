#ifndef SECUREKG_ENTROPY_OS_ENTROPY_H_
#define SECUREKG_ENTROPY_OS_ENTROPY_H_

#include <cstddef>
#include <cstdint>
#include <vector>

namespace securekg::entropy {

using Bytes = std::vector<std::uint8_t>;

// Cryptographically secure random bytes from the operating system CSPRNG.
//
// This deliberately uses the kernel syscalls (getrandom / getentropy /
// BCryptGenRandom) rather than opening "/dev/urandom" as a file: a file
// descriptor can be exhausted, closed, or redirected (e.g. inside a chroot or a
// seccomp sandbox), which has caused real-world key-generation failures. The
// syscall path cannot be starved that way. A "/dev/urandom" read is kept only
// as a last-resort fallback when the syscall is unavailable.
//
// Throws std::runtime_error if no secure source can be obtained.
void os_random(std::uint8_t* buf, std::size_t len);
Bytes os_random(std::size_t len);

// Human-readable name of the backend chosen at compile time.
const char* os_backend();

}  // namespace securekg::entropy

#endif  // SECUREKG_ENTROPY_OS_ENTROPY_H_
