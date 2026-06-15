// libFuzzer harness for the statistical test suite and the entropy estimator.
// Feeds arbitrary bytes (including tiny / empty / degenerate inputs) through
// every test to flush out out-of-bounds reads, division-by-zero or NaN paths.
//
// Build (clang):
//   clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -Iinclude \
//     fuzz/fuzz_sts.cpp src/**/*.cpp -o fuzz_sts
#include <cmath>
#include <cstdint>
#include <vector>

#include "securekg/entropy/min_entropy.h"
#include "securekg/stats/sts.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  std::vector<std::uint8_t> bytes(data, data + size);

  for (const auto& r : securekg::stats::run_all(bytes)) {
    if (r.applicable) {
      // A valid p-value must always be a finite number in [0, 1].
      if (!std::isfinite(r.p_value) || r.p_value < 0.0 || r.p_value > 1.0)
        __builtin_trap();
    }
  }

  auto e = securekg::entropy::estimate_entropy(bytes);
  if (!std::isfinite(e.mcv_min_entropy_per_byte) ||
      e.mcv_min_entropy_per_byte < 0.0)
    __builtin_trap();

  return 0;
}
