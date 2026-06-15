# SecureKeygen

**A from-scratch, dependency-free CSPRNG and entropy toolkit in C++17 — built on the NIST cryptographic standards and validated against the official test vectors.**

[![CI](https://github.com/Je1al/Secure_key_generator/actions/workflows/ci.yml/badge.svg)](https://github.com/Je1al/Secure_key_generator/actions/workflows/ci.yml)
![C++17](https://img.shields.io/badge/C%2B%2B-17-0d0d0d?style=flat-square&logo=cplusplus&logoColor=white)
![NIST SP 800-90A](https://img.shields.io/badge/NIST-SP%20800--90A%2F90B%2F800--22-0d0d0d?style=flat-square)
![Dependencies](https://img.shields.io/badge/dependencies-none-0d0d0d?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-0d0d0d?style=flat-square)

SecureKeygen generates cryptographic keys the way a real system should: a kernel-seeded entropy source feeds a standardized **deterministic random bit generator (DRBG)**, and the output can be measured by an implementation of the NIST randomness-testing and entropy-estimation suites. Every cryptographic primitive — SHA-256, HMAC, HKDF, PBKDF2, AES, and all three SP 800-90A DRBGs — is implemented from scratch with **no third-party dependencies**, and each is checked against the published FIPS / RFC / NIST CAVP test vectors in CI.

> ⚠️ This is an educational, audit-yourself project, not a certified cryptographic module. For production, use a vetted library (libsodium, BoringSSL, OpenSSL) or the OS CSPRNG directly. The value here is a transparent, standards-faithful, test-driven implementation you can read end to end. See [Security considerations](#security-considerations).

---

## Why this exists

"Generate a random key" sounds trivial, but doing it *correctly* touches the parts of cryptographic engineering that actually matter in the field — especially in **embedded and automotive security**, where keys are provisioned into ECUs and HSMs and a weak RNG silently undermines every downstream protocol:

- **Where does entropy come from**, and how do you avoid the classic failure modes (a `/dev/urandom` file descriptor that gets closed in a sandbox, an RNG used before the pool is seeded)?
- **How do you turn raw entropy into an unlimited keystream** without weakening it — i.e. a real DRBG with a defined reseed strategy, not an ad-hoc hash loop?
- **How do you prove the output is good?** Statistical test suites (SP 800-22) and min-entropy estimation (SP 800-90B) — and knowing what those tests can and cannot tell you.

This project answers all three with code that maps directly onto the relevant standards.

---

## Highlights

- **OS entropy via syscalls, not files** — `getrandom(2)` (Linux), `getentropy(2)` (macOS/BSD), `BCryptGenRandom` (Windows), with `/dev/urandom` only as a last-resort fallback. Avoids the file-descriptor starvation class of bugs.
- **All three NIST SP 800-90A DRBGs from scratch** — HMAC-DRBG (SHA-256), Hash-DRBG (SHA-256), and CTR-DRBG (AES-256), each with the full instantiate / reseed / generate lifecycle, reseed counters, additional-input support, and per-request output limits.
- **Validated against official NIST CAVP known-answer vectors** — not just "looks random". The DRBG outputs match NIST's published response files byte-for-byte.
- **NIST SP 800-22 statistical test suite** (subset) — Monobit, Block Frequency, Runs, Longest Run of Ones, Cumulative Sums, Approximate Entropy and Serial, each returning a real p-value via the incomplete-gamma / erfc machinery.
- **NIST SP 800-90B min-entropy estimation** — the Most Common Value estimator with a 99 % upper confidence bound, reported per byte and per bit.
- **Key derivation** — HKDF-SHA256 (RFC 5869) and PBKDF2-HMAC-SHA256 (RFC 8018).
- **Engineering rigor** — zero dependencies, `-Wall -Wextra -Wpedantic` clean, AddressSanitizer + UndefinedBehaviorSanitizer clean, libFuzzer harnesses, GitHub Actions CI across GCC/Clang on Linux and macOS, plus Make and CMake builds.
- **Defensive coding** — constant-time tag comparison, best-effort `secure_zero` wiping of key material and DRBG state, careful integer handling.

---

## Validation & correctness

Everything below is checked automatically by the test binary (`make test`) and the runtime self-test (`securekg selftest`):

| Component | Standard | Validated against |
|---|---|---|
| SHA-256 | FIPS 180-4 | FIPS vectors: `"abc"`, empty, 10⁶×`'a'` |
| HMAC-SHA256 | FIPS 198-1 / RFC 2104 | RFC 4231 test cases 1 & 2 |
| HKDF-SHA256 | RFC 5869 | RFC 5869 Test Case 1 (PRK + OKM) |
| PBKDF2-HMAC-SHA256 | RFC 8018 | Published SHA-256 vectors (c = 1, c = 4096) |
| AES-128 / AES-256 | FIPS 197 | FIPS 197 Appendix C |
| HMAC-DRBG (SHA-256) | NIST SP 800-90A | **NIST CAVP** known-answer vectors |
| Hash-DRBG (SHA-256) | NIST SP 800-90A | **NIST CAVP** known-answer vectors |
| CTR-DRBG (AES-256, no df) | NIST SP 800-90A | **NIST CAVP** known-answer vectors |
| SP 800-22 test suite | NIST SP 800-22 Rev. 1a | Calibration: ~1 % false-reject rate at α = 0.01 |
| MCV min-entropy | NIST SP 800-90B §6.3.1 | Bounds checked on CSPRNG vs degenerate input |

The DRBG vectors include both the no-personalization/no-additional-input cases and the personalization-plus-additional-input cases, so those code paths are covered too.

```
$ securekg selftest
...
[NIST SP 800-90A CAVP]
  HMAC-DRBG (no perso/addin)        PASS
  HMAC-DRBG (perso+addin)           PASS
  Hash-DRBG (no perso/addin)        PASS
  Hash-DRBG (perso+addin)           PASS
  CTR-DRBG (no perso/addin)         PASS
  CTR-DRBG (perso+addin)            PASS

17/17 known-answer tests passed.
```

---

## Build

No dependencies beyond a C++17 compiler.

```bash
make                # build the static library, the `securekg` CLI and the tests
make test           # run unit + known-answer tests
make selftest       # run the embedded NIST/FIPS/RFC known-answer vectors
make asan           # rebuild and run tests under ASan + UBSan
```

Or with CMake:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

The binaries land in `build/` (`build/securekg`, `build/securekg_tests`).

---

## CLI usage

```bash
# Generate a 256-bit key (hex by default)
securekg keygen --bits 256

# 32 random bytes, base64, using the CTR-DRBG (AES-256) mechanism
securekg keygen --bytes 32 --drbg ctr --format base64

# A 128-bit key as a ready-to-paste C array
securekg keygen --bits 128 --format c-array --name aes_key

# Derive a key from a password (PBKDF2-HMAC-SHA256, RFC 8018)
securekg derive --password "correct horse battery staple" --iterations 600000

# Run the NIST SP 800-22 statistical test suite on a byte stream
securekg keygen --bytes 125000 --format raw | securekg test

# Estimate min-entropy (NIST SP 800-90B) of a sample
securekg keygen --bytes 4096 --format raw | securekg entropy

# Deterministic DRBG output from explicit seed material (reproducible)
securekg drbg --drbg hmac --entropy 000102...1f --nonce 2021...27 --bytes 48
```

`securekg <command> --help` documents each command. DRBG choices are `hmac`, `hash`, `ctr`; output formats are `hex`, `base64`, `binary`, `raw`, `c-array`.

---

## Library usage

```cpp
#include "securekg/keygen/csprng.h"
#include "securekg/stats/sts.h"
#include "securekg/util/bytes.h"

using namespace securekg;

int main() {
  // OS-seeded, self-reseeding CSPRNG backed by HMAC-DRBG(SHA-256).
  keygen::Csprng rng(keygen::DrbgKind::HmacSha256);
  auto key = rng.random_bytes(32);
  printf("key = %s\n", util::to_hex(key).c_str());

  // Sanity-check a sample with the SP 800-22 suite.
  for (const auto& t : stats::run_all(rng.random_bytes(125000)))
    if (t.applicable)
      printf("%-26s p=%.4f %s\n", t.name.c_str(), t.p_value,
             t.passed ? "pass" : "fail");
}
```

---

## Project layout

```
include/securekg/        public headers (mirrors src/)
  crypto/                SHA-256, HMAC, HKDF/PBKDF2, AES
  drbg/                  SP 800-90A: HMAC-DRBG, Hash-DRBG, CTR-DRBG
  entropy/               OS entropy source, SP 800-90B estimator
  stats/                 SP 800-22 statistical tests
  keygen/                CSPRNG facade + key formatting
  util/                  encoding, constant-time compare, secure wipe
src/                     implementations
tools/securekg_main.cpp  the CLI
tests/                   unit + known-answer test runner
fuzz/                    libFuzzer harnesses (DRBG / STS / encoding)
docs/                    ARCHITECTURE, THREAT_MODEL, STANDARDS
```

---

## Design notes

- **Entropy source.** Opening `/dev/urandom` as a file is the textbook way to *almost* get this right — and then a closed/exhausted descriptor inside a sandbox returns short or zero reads. SecureKeygen calls the kernel syscalls directly and treats the file only as a fallback. See [`os_entropy.cpp`](src/entropy/os_entropy.cpp).
- **DRBG, not a hash loop.** Output is produced by a standardized DRBG with a defined key schedule, a reseed counter, optional additional input, and a per-request limit of 2¹⁹ bits, after which the CSPRNG transparently reseeds from the OS.
- **Mechanism independence.** All three DRBGs implement one interface (`drbg::Drbg`), so the CSPRNG facade is agnostic to the chosen mechanism.
- **Hygiene.** Key material and DRBG state are wiped with a `secure_zero` the optimizer cannot elide; MAC/tag checks use a constant-time comparison.

---

## Why this matters for embedded & automotive security

Automotive platforms (AUTOSAR SecOC, the EVITA/SHE HSM model, ISO 21434) depend on key material being generated and seeded correctly inside resource-constrained ECUs. The exact concerns this project models — choosing a standardized DRBG, seeding it from a trustworthy entropy source, respecting reseed intervals, and being able to *assess* an entropy source with SP 800-90B / SP 800-22 — are the same ones a vehicle HSM crypto stack must get right. The implementation is intentionally dependency-free and C++17, the way embedded firmware tends to be.

---

## Statistical tests implemented (SP 800-22 Rev. 1a)

Frequency (Monobit) · Frequency within a Block · Runs · Longest Run of Ones in a Block · Cumulative Sums (forward & backward) · Approximate Entropy · Serial. Each returns a p-value; a sequence "passes" at α = 0.01 when p ≥ α. A pass is **necessary but not sufficient** evidence of randomness — these tests detect specific structural defects, they do not prove cryptographic strength.

---

## Security considerations

- **Not a certified module.** No FIPS 140-3 validation, no formal audit, no side-channel hardening beyond constant-time comparisons. Timing/cache side channels in the from-scratch AES and the math routines have not been analyzed.
- **Trust anchor is the OS CSPRNG.** The DRBGs are only as strong as the entropy seeding them; this project relies on the kernel source being healthy.
- **Use the right tool in production.** For real systems, prefer the OS CSPRNG (`getrandom`/`BCryptGenRandom`) or a vetted library. This codebase exists to make the standards legible and testable.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full model.

---

## Standards referenced

- **FIPS 180-4** — SHA-256
- **FIPS 197** — AES
- **FIPS 198-1 / RFC 2104** — HMAC
- **RFC 5869** — HKDF · **RFC 8018** — PBKDF2
- **NIST SP 800-90A Rev. 1** — DRBG mechanisms (HMAC / Hash / CTR)
- **NIST SP 800-90B** — entropy source min-entropy estimation
- **NIST SP 800-22 Rev. 1a** — statistical test suite for RNGs

Further detail and the standard-to-code mapping is in [`docs/STANDARDS.md`](docs/STANDARDS.md).

---

## License

MIT — see [LICENSE](LICENSE).
