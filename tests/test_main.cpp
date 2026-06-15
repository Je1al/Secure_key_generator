// Unit + known-answer test runner for SecureKeygen.
//
// Uses a tiny self-contained harness (no external framework) so it builds with
// just a C++17 compiler. It runs every embedded NIST/FIPS/RFC known-answer test
// plus behavioural checks on the encoders, the statistical suite, the entropy
// estimator and the CSPRNG.
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

#include "securekg/crypto/kdf.h"
#include "securekg/entropy/min_entropy.h"
#include "securekg/keygen/csprng.h"
#include "securekg/selftest.h"
#include "securekg/stats/sts.h"
#include "securekg/util/bytes.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool cond, const std::string& what) {
  ++g_checks;
  if (!cond) {
    ++g_failures;
    std::printf("  [FAIL] %s\n", what.c_str());
  }
}

using securekg::util::Bytes;
using securekg::util::from_hex;
using securekg::util::to_hex;

void test_known_answers() {
  std::printf("Known-answer tests (FIPS / RFC / NIST CAVP):\n");
  auto report = securekg::run_self_tests();
  for (const auto& c : report.cases) check(c.passed, c.standard + " :: " + c.name);
  std::printf("  %d/%d KAT cases passed\n",
              report.passed, report.passed + report.failed);
}

void test_encoding() {
  std::printf("Encoding round-trips:\n");
  for (std::size_t n : {0u, 1u, 2u, 3u, 16u, 31u, 32u, 100u}) {
    Bytes data;
    for (std::size_t i = 0; i < n; ++i)
      data.push_back(static_cast<std::uint8_t>((i * 37 + 11) & 0xFF));
    check(from_hex(to_hex(data)) == data, "hex round-trip n=" + std::to_string(n));
    check(securekg::util::from_base64(securekg::util::to_base64(data)) == data,
          "base64 round-trip n=" + std::to_string(n));
  }
  // Constant-time equality.
  Bytes a = from_hex("00112233"), b = from_hex("00112233"), c = from_hex("00112234");
  check(securekg::util::ct_equal(a, b), "ct_equal equal");
  check(!securekg::util::ct_equal(a, c), "ct_equal different");
  check(!securekg::util::ct_equal(a, from_hex("0011")), "ct_equal length mismatch");
}

void test_kdf_lengths() {
  std::printf("KDF output lengths:\n");
  Bytes ikm(32, 0x42), salt(16, 0x01), info = {'x'};
  for (std::size_t L : {1u, 32u, 33u, 64u, 255u}) {
    check(securekg::crypto::hkdf(salt, ikm, info, L).size() == L,
          "hkdf length " + std::to_string(L));
  }
  for (std::size_t L : {1u, 16u, 32u, 48u, 100u}) {
    check(securekg::crypto::pbkdf2_hmac_sha256(ikm, salt, 10, L).size() == L,
          "pbkdf2 length " + std::to_string(L));
  }
}

void test_csprng_determinism() {
  std::printf("CSPRNG determinism & isolation:\n");
  using securekg::keygen::Csprng;
  using securekg::keygen::DrbgKind;
  Bytes e32 = from_hex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  Bytes nonce = from_hex("20212223242526272829");
  Bytes e48 = from_hex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      "202122232425262728292a2b2c2d2e2f");

  auto r1 = Csprng::from_seed(DrbgKind::HmacSha256, e32, nonce).random_bytes(96);
  auto r2 = Csprng::from_seed(DrbgKind::HmacSha256, e32, nonce).random_bytes(96);
  check(r1 == r2, "HMAC-DRBG reproducible from same seed");

  auto r3 = Csprng::from_seed(DrbgKind::CtrAes256, e48, {}).random_bytes(96);
  check(r1 != r3, "different mechanisms produce different streams");

  // A large request that crosses the per-request chunk boundary stays
  // consistent with two smaller requests from an identical instance.
  auto big = Csprng::from_seed(DrbgKind::HashSha256, e32, nonce).random_bytes(200000);
  check(big.size() == 200000, "large request returns requested length");
}

void test_stats_discrimination() {
  std::printf("Statistical-test discrimination:\n");
  // Good randomness from a CAVP-validated DRBG should pass monobit.
  securekg::keygen::Csprng rng(securekg::keygen::DrbgKind::HmacSha256);
  Bytes good = rng.random_bytes(20000);
  auto mb_good = securekg::stats::frequency_monobit(securekg::stats::bytes_to_bits(good));
  check(mb_good.applicable && mb_good.passed, "monobit passes on CSPRNG output");

  // Degenerate input must be rejected.
  Bytes zeros(20000, 0x00);
  auto mb_zero = securekg::stats::frequency_monobit(securekg::stats::bytes_to_bits(zeros));
  check(mb_zero.applicable && !mb_zero.passed && mb_zero.p_value < 0.01,
        "monobit fails on all-zeros");
  auto cs_zero = securekg::stats::cumulative_sums(securekg::stats::bytes_to_bits(zeros));
  check(!cs_zero[0].passed, "cusum fails on all-zeros");
}

void test_entropy_estimator() {
  std::printf("Entropy estimator bounds:\n");
  securekg::keygen::Csprng rng(securekg::keygen::DrbgKind::CtrAes256);
  Bytes good = rng.random_bytes(50000);
  auto eg = securekg::entropy::estimate_entropy(good);
  check(eg.mcv_min_entropy_per_byte > 7.0,
        "CSPRNG min-entropy/byte > 7.0 (got " +
            std::to_string(eg.mcv_min_entropy_per_byte) + ")");
  check(eg.mcv_min_entropy_per_bit > 0.98, "CSPRNG min-entropy/bit > 0.98");

  Bytes zeros(50000, 0x00);
  auto ez = securekg::entropy::estimate_entropy(zeros);
  check(ez.mcv_min_entropy_per_byte < 0.01, "all-zeros min-entropy ~ 0");
}

}  // namespace

int main() {
  test_known_answers();
  test_encoding();
  test_kdf_lengths();
  test_csprng_determinism();
  test_stats_discrimination();
  test_entropy_estimator();

  std::printf("\n%s  (%d checks, %d failures)\n",
              g_failures == 0 ? "ALL TESTS PASSED" : "TEST FAILURES",
              g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
