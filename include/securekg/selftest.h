#ifndef SECUREKG_SELFTEST_H_
#define SECUREKG_SELFTEST_H_

#include <string>
#include <vector>

namespace securekg {

// A single known-answer-test outcome.
struct SelfTestCase {
  std::string name;
  std::string standard;  // e.g. "FIPS 180-4", "NIST SP 800-90A CAVP"
  bool passed;
};

struct SelfTestReport {
  std::vector<SelfTestCase> cases;
  bool all_passed = true;
  int passed = 0;
  int failed = 0;
};

// Runs every embedded known-answer test (hash / HMAC / KDF / AES / the three
// DRBGs) against official FIPS, RFC and NIST CAVP vectors. This is what the
// `securekg selftest` command and the unit-test binary both call, so the same
// validation runs at build time and on demand in the field.
SelfTestReport run_self_tests();

}  // namespace securekg

#endif  // SECUREKG_SELFTEST_H_
