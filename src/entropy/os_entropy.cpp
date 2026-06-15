#include "securekg/entropy/os_entropy.h"

#include <stdexcept>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__unix__)
#include <sys/random.h>
#endif

// Shared "/dev/urandom" fallback for the rare case the syscall is missing.
#if !defined(_WIN32)
#include <cstdio>
#endif

namespace securekg::entropy {
namespace {

#if !defined(_WIN32)
void read_dev_urandom(std::uint8_t* buf, std::size_t len) {
  std::FILE* f = std::fopen("/dev/urandom", "rb");
  if (!f) throw std::runtime_error("os_random: /dev/urandom unavailable");
  std::size_t got = std::fread(buf, 1, len, f);
  std::fclose(f);
  if (got != len) throw std::runtime_error("os_random: short read from /dev/urandom");
}
#endif

}  // namespace

void os_random(std::uint8_t* buf, std::size_t len) {
  if (len == 0) return;

#if defined(_WIN32)
  NTSTATUS s = BCryptGenRandom(nullptr, buf, static_cast<ULONG>(len),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (s != 0) throw std::runtime_error("os_random: BCryptGenRandom failed");

#elif defined(__linux__)
  std::size_t off = 0;
  while (off < len) {
    ssize_t r = getrandom(buf + off, len - off, 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      if (errno == ENOSYS) {  // kernel too old for getrandom
        read_dev_urandom(buf + off, len - off);
        return;
      }
      throw std::runtime_error("os_random: getrandom failed");
    }
    off += static_cast<std::size_t>(r);
  }

#elif defined(__APPLE__) || defined(__unix__)
  // getentropy returns at most 256 bytes per call.
  std::size_t off = 0;
  while (off < len) {
    std::size_t chunk = (len - off) < 256 ? (len - off) : 256;
    if (getentropy(buf + off, chunk) != 0) {
      read_dev_urandom(buf + off, len - off);
      return;
    }
    off += chunk;
  }

#else
  read_dev_urandom(buf, len);
#endif
}

Bytes os_random(std::size_t len) {
  Bytes out(len);
  os_random(out.data(), len);
  return out;
}

const char* os_backend() {
#if defined(_WIN32)
  return "BCryptGenRandom";
#elif defined(__linux__)
  return "getrandom(2)";
#elif defined(__APPLE__) || defined(__unix__)
  return "getentropy(2)";
#else
  return "/dev/urandom";
#endif
}

}  // namespace securekg::entropy
