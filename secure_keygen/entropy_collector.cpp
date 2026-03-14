#include "entropy_collector.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <functional>
#include <memory>
#include <random>
#include <thread>
#include <vector>

#if defined(_WIN32)
  #include <windows.h>
#else
  #include <unistd.h>
#endif

namespace secure_keygen {

void EntropyCollector::append_u64(std::vector<uint8_t>& out, std::uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void EntropyCollector::append_bytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}

std::vector<uint8_t> EntropyCollector::os_random_bytes(std::size_t count) const {
  std::vector<uint8_t> out;
  out.reserve(count);

#if defined(__APPLE__) || defined(__unix__)
  std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
  if (urandom) {
    out.resize(count);
    urandom.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(count));
    if (urandom.gcount() == static_cast<std::streamsize>(count)) {
      return out;
    }
    out.clear();
  }
#endif

  std::random_device rd; // Typically backed by OS entropy sources.
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(static_cast<uint8_t>(rd() & 0xFFu));
  }
  return out;
}

std::vector<uint8_t> EntropyCollector::timing_bytes() const {
  std::vector<uint8_t> out;
  out.reserve(32);

  auto now_high = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  auto now_steady = std::chrono::steady_clock::now().time_since_epoch().count();
  auto now_system = std::chrono::system_clock::now().time_since_epoch().count();

  append_u64(out, static_cast<std::uint64_t>(now_high));
  append_u64(out, static_cast<std::uint64_t>(now_steady));
  append_u64(out, static_cast<std::uint64_t>(now_system));

  return out;
}

std::vector<uint8_t> EntropyCollector::process_bytes() const {
  std::vector<uint8_t> out;
  out.reserve(16);

#if defined(_WIN32)
  std::uint64_t pid = static_cast<std::uint64_t>(GetCurrentProcessId());
#else
  std::uint64_t pid = static_cast<std::uint64_t>(getpid());
#endif
  std::uint64_t tid = static_cast<std::uint64_t>(
      std::hash<std::thread::id>{}(std::this_thread::get_id()));

  append_u64(out, pid);
  append_u64(out, tid);
  return out;
}

std::vector<uint8_t> EntropyCollector::memory_bytes() const {
  std::vector<uint8_t> out;
  out.reserve(32);

  // Addresses are not secret, but they add variability across runs and processes.
  int stack_var = 0;
  auto heap_ptr = std::make_unique<int>(42);

  std::uintptr_t stack_addr = reinterpret_cast<std::uintptr_t>(&stack_var);
  std::uintptr_t heap_addr = reinterpret_cast<std::uintptr_t>(heap_ptr.get());
  std::uintptr_t this_addr = reinterpret_cast<std::uintptr_t>(this);

  append_u64(out, static_cast<std::uint64_t>(stack_addr));
  append_u64(out, static_cast<std::uint64_t>(heap_addr));
  append_u64(out, static_cast<std::uint64_t>(this_addr));

  return out;
}

std::vector<uint8_t> EntropyCollector::collect(std::size_t min_bytes) const {
  std::vector<uint8_t> pool;
  pool.reserve(min_bytes);

  append_bytes(pool, os_random_bytes(32));
  append_bytes(pool, timing_bytes());
  append_bytes(pool, process_bytes());
  append_bytes(pool, memory_bytes());

  if (pool.size() < min_bytes) {
    append_bytes(pool, os_random_bytes(min_bytes - pool.size()));
  }

  return pool;
}

} // namespace secure_keygen
