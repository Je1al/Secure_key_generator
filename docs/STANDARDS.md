# Standards mapping

Every cryptographic component maps to a published standard and is validated
against that standard's test vectors. This table is the quick reference; the
notes below add detail on the less obvious choices.

| Standard | What it specifies | Where it lives | Validation |
|---|---|---|---|
| FIPS 180-4 | SHA-256 | `crypto/sha256.*` | `"abc"`, empty, 10⁶×`'a'` |
| FIPS 198-1, RFC 2104 | HMAC | `crypto/hmac_sha256.*` | RFC 4231 cases 1–2 |
| RFC 5869 | HKDF (extract/expand) | `crypto/kdf.*` | RFC 5869 Test Case 1 |
| RFC 8018 | PBKDF2 | `crypto/kdf.*` | SHA-256 vectors (c=1, c=4096) |
| FIPS 197 | AES block cipher | `crypto/aes.*` | FIPS 197 Appendix C (128 & 256) |
| SP 800-38A | CTR mode | `crypto/aes.*` (`ctr_xor`) | exercised via CTR-DRBG |
| SP 800-90A Rev. 1 | HMAC/Hash/CTR DRBG | `drbg/*` | **NIST CAVP** known-answer vectors |
| SP 800-90B | Min-entropy estimation | `entropy/min_entropy.*` | MCV estimator, bounds checked |
| SP 800-22 Rev. 1a | RNG statistical tests | `stats/sts.*` | ~1 % false-reject at α=0.01 |

## Notes

### SP 800-90A — DRBG construction
All three mechanisms follow the pseudocode in SP 800-90A Rev. 1 directly:

- **HMAC-DRBG (§10.1.2).** State `(K, V)`; the `Update` function derives a fresh
  `K` and `V` from provided data; `Generate` streams `V = HMAC(K, V)` blocks.
- **Hash-DRBG (§10.1.1).** State `(V, C)` with `seedlen = 440` bits.
  `Hash_df` (§10.3.1) derives the initial state; `Hashgen` produces output;
  generation updates `V = (V + Hash(0x03‖V) + C + reseed_counter) mod 2^seedlen`,
  which requires big-endian modular addition over the 55-byte state.
- **CTR-DRBG (§10.2.1), AES-256, no df.** State `(Key, V)`. Because no derivation
  function is used, the seed material must be exactly `keylen + blocklen = 48`
  bytes of full entropy — the CSPRNG facade enforces this by drawing 48 bytes
  from the OS source.

**Validation against CAVP.** The known-answer tests use NIST's *no-reseed*
response files: instantiate, call `Generate` twice, and compare the second
output to the published `ReturnedBits`. Both the bare case and the
personalization-string-plus-additional-input case are checked, so every branch
of the generate/update logic is exercised.

### SP 800-90B — entropy estimation
The **Most Common Value** estimator (§6.3.1) takes `L` samples, finds the count
`c` of the most frequent value, and forms a 99 % upper confidence bound
`p_u = p̂ + 2.576·√(p̂(1−p̂)/(L−1))` with `p̂ = c/L`. The min-entropy estimate is
`−log₂(min(1, p_u))`. It is reported over 8-bit symbols and over the raw bit
stream. Shannon entropy is shown for context but is an *upper* bound, never the
security figure.

### SP 800-22 — statistical tests
P-values use `erfc` (for the normal-approximation tests) and a regularized upper
incomplete gamma function `igamc` (for the chi-square tests), implemented with
the classic Cephes series/continued-fraction algorithms — the same approach as
the reference NIST STS. The suite implemented here is a subset chosen to cover
the main failure modes a defective RNG exhibits: global and block-level bias,
run structure, longest-run distribution, random-walk excursions, and short-block
pattern frequencies (Approximate Entropy, Serial). Parameters (block size `M`,
pattern length `m`) are selected automatically from the input length.

### Reference test vectors
The NIST CAVP DRBG vectors are the official Cryptographic Algorithm Validation
Program response files (`drbgvectors_no_reseed/{HMAC,Hash,CTR}_DRBG.rsp`). The
hash/HMAC/HKDF/PBKDF2/AES vectors come from the corresponding FIPS publications
and RFCs cited above.
