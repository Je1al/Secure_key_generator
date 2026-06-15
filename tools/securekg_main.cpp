// securekg -- command-line front-end for the SecureKeygen toolkit.
//
// Subcommands:
//   keygen    generate cryptographic keys from the OS-seeded CSPRNG
//   derive    derive a key from a password with PBKDF2-HMAC-SHA256
//   test      run the NIST SP 800-22 statistical test suite on input
//   entropy   estimate min-entropy of input (NIST SP 800-90B MCV)
//   drbg      deterministic DRBG output from explicit seed material
//   selftest  run all known-answer tests (FIPS / RFC / NIST CAVP)
//   version   print version and build information
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "securekg/entropy/min_entropy.h"
#include "securekg/entropy/os_entropy.h"
#include "securekg/crypto/kdf.h"
#include "securekg/keygen/csprng.h"
#include "securekg/keygen/key.h"
#include "securekg/selftest.h"
#include "securekg/stats/sts.h"
#include "securekg/util/bytes.h"

namespace {

using securekg::util::Bytes;

constexpr char kVersion[] = "1.0.0";

// Minimal flag parser: collects "--name value" and "--name" (bool) pairs.
struct Args {
  std::map<std::string, std::string> opts;
  std::vector<std::string> positional;

  bool has(const std::string& k) const { return opts.count(k) > 0; }
  std::string get(const std::string& k, const std::string& def = "") const {
    auto it = opts.find(k);
    return it == opts.end() ? def : it->second;
  }
  long get_long(const std::string& k, long def) const {
    auto it = opts.find(k);
    if (it == opts.end() || it->second.empty()) return def;
    return std::stol(it->second);
  }
};

Args parse_args(int argc, char** argv, int start) {
  Args a;
  for (int i = start; i < argc; ++i) {
    std::string tok = argv[i];
    if (tok.rfind("--", 0) == 0) {
      std::string key = tok.substr(2);
      if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
        a.opts[key] = argv[++i];
      } else {
        a.opts[key] = "";  // boolean flag
      }
    } else {
      a.positional.push_back(tok);
    }
  }
  return a;
}

Bytes read_all_input(const Args& a) {
  std::string contents;
  if (a.has("file")) {
    std::ifstream f(a.get("file"), std::ios::binary);
    if (!f) throw std::runtime_error("cannot open file: " + a.get("file"));
    std::ostringstream ss;
    ss << f.rdbuf();
    contents = ss.str();
  } else {
    std::ostringstream ss;
    ss << std::cin.rdbuf();
    contents = ss.str();
  }
  if (a.has("hex")) return securekg::util::from_hex(contents);
  return Bytes(contents.begin(), contents.end());
}

void print_usage() {
  std::cout <<
      "securekg " << kVersion << " -- CSPRNG & entropy toolkit (NIST SP 800-90A/90B/800-22)\n\n"
      "Usage: securekg <command> [options]\n\n"
      "Commands:\n"
      "  keygen     Generate keys from the OS-seeded CSPRNG\n"
      "  derive     Derive a key from a password (PBKDF2-HMAC-SHA256)\n"
      "  test       Run the NIST SP 800-22 statistical test suite\n"
      "  entropy    Estimate min-entropy (NIST SP 800-90B MCV)\n"
      "  drbg       Deterministic DRBG output from explicit seed material\n"
      "  selftest   Run all known-answer tests (FIPS / RFC / NIST CAVP)\n"
      "  version    Print version information\n\n"
      "Run 'securekg <command> --help' for command-specific options.\n";
}

int cmd_keygen(const Args& a) {
  if (a.has("help")) {
    std::cout << "Usage: securekg keygen [--bits N | --bytes N] "
                 "[--drbg hmac|hash|ctr] [--format hex|base64|binary|raw|c-array] "
                 "[--count K] [--name NAME]\n";
    return 0;
  }
  std::size_t bytes;
  if (a.has("bits"))
    bytes = static_cast<std::size_t>(a.get_long("bits", 256)) / 8;
  else
    bytes = static_cast<std::size_t>(a.get_long("bytes", 32));
  if (bytes == 0) {
    std::cerr << "error: key size must be > 0\n";
    return 1;
  }

  securekg::keygen::DrbgKind kind = securekg::keygen::DrbgKind::HmacSha256;
  if (a.has("drbg") && !securekg::keygen::parse_drbg_kind(a.get("drbg"), kind)) {
    std::cerr << "error: unknown DRBG '" << a.get("drbg") << "'\n";
    return 1;
  }
  securekg::keygen::OutputFormat fmt = securekg::keygen::OutputFormat::Hex;
  if (a.has("format") && !securekg::keygen::parse_format(a.get("format"), fmt)) {
    std::cerr << "error: unknown format '" << a.get("format") << "'\n";
    return 1;
  }

  long count = a.get_long("count", 1);
  std::string name = a.get("name", "key");
  securekg::keygen::Csprng rng(kind);
  for (long i = 0; i < count; ++i) {
    Bytes key = rng.random_bytes(bytes);
    std::string out =
        securekg::keygen::format_key(key, fmt, name);
    if (fmt == securekg::keygen::OutputFormat::Raw)
      std::cout.write(out.data(), static_cast<std::streamsize>(out.size()));
    else
      std::cout << out << "\n";
    securekg::util::secure_zero(key);
  }
  return 0;
}

int cmd_derive(const Args& a) {
  if (a.has("help") || !a.has("password")) {
    std::cout << "Usage: securekg derive --password PW [--salt HEX] "
                 "[--iterations C] [--bytes N] [--format ...]\n"
                 "  Derives a key with PBKDF2-HMAC-SHA256 (RFC 8018).\n";
    return a.has("help") ? 0 : 1;
  }
  std::string pw = a.get("password");
  Bytes password(pw.begin(), pw.end());
  Bytes salt;
  if (a.has("salt"))
    salt = securekg::util::from_hex(a.get("salt"));
  else
    salt = securekg::entropy::os_random(16);  // random salt if none supplied

  std::uint32_t iters =
      static_cast<std::uint32_t>(a.get_long("iterations", 600000));
  std::size_t dk = static_cast<std::size_t>(a.get_long("bytes", 32));

  securekg::keygen::OutputFormat fmt = securekg::keygen::OutputFormat::Hex;
  if (a.has("format") && !securekg::keygen::parse_format(a.get("format"), fmt)) {
    std::cerr << "error: unknown format '" << a.get("format") << "'\n";
    return 1;
  }

  Bytes key = securekg::crypto::pbkdf2_hmac_sha256(password, salt, iters, dk);
  if (!a.has("salt"))
    std::cerr << "salt (hex): " << securekg::util::to_hex(salt) << "\n";
  std::string out = securekg::keygen::format_key(key, fmt);
  if (fmt == securekg::keygen::OutputFormat::Raw)
    std::cout.write(out.data(), static_cast<std::streamsize>(out.size()));
  else
    std::cout << out << "\n";
  securekg::util::secure_zero(key);
  return 0;
}

int cmd_test(const Args& a) {
  if (a.has("help")) {
    std::cout << "Usage: securekg test [--file PATH] [--hex] [--alpha A]\n"
                 "  Reads bytes from --file or stdin and runs SP 800-22.\n";
    return 0;
  }
  Bytes data = read_all_input(a);
  double alpha = a.has("alpha") ? std::stod(a.get("alpha")) : securekg::stats::kAlpha;
  std::cout << "NIST SP 800-22 statistical test suite (alpha=" << alpha
            << ", n=" << data.size() * 8 << " bits)\n";
  std::cout << std::string(64, '-') << "\n";
  int passed = 0, total = 0;
  for (const auto& t : securekg::stats::run_all(data, alpha)) {
    if (!t.applicable) {
      std::printf("  %-28s  N/A  (%s)\n", t.name.c_str(), t.detail.c_str());
      continue;
    }
    ++total;
    if (t.passed) ++passed;
    std::printf("  %-28s  p=%.6f  %s\n", t.name.c_str(), t.p_value,
                t.passed ? "PASS" : "FAIL");
  }
  std::cout << std::string(64, '-') << "\n";
  std::cout << "  " << passed << "/" << total << " tests passed\n";
  return passed == total ? 0 : 2;
}

int cmd_entropy(const Args& a) {
  if (a.has("help")) {
    std::cout << "Usage: securekg entropy [--file PATH] [--hex]\n"
                 "  Estimates min-entropy (NIST SP 800-90B MCV estimator).\n";
    return 0;
  }
  Bytes data = read_all_input(a);
  auto e = securekg::entropy::estimate_entropy(data);
  std::printf("Samples            : %zu bytes (%zu bits)\n", e.byte_count, e.bit_count);
  std::printf("Shannon entropy    : %.4f bits/byte  (upper bound only)\n",
              e.shannon_per_byte);
  std::printf("MCV min-entropy    : %.4f bits/byte  (SP 800-90B 6.3.1)\n",
              e.mcv_min_entropy_per_byte);
  std::printf("MCV min-entropy    : %.4f bits/bit\n", e.mcv_min_entropy_per_bit);
  std::printf("Est. total entropy : %.1f bits\n", e.total_min_entropy_bits());
  return 0;
}

int cmd_drbg(const Args& a) {
  if (a.has("help") || !a.has("entropy")) {
    std::cout << "Usage: securekg drbg --drbg hmac|hash|ctr --entropy HEX "
                 "[--nonce HEX] [--perso HEX] [--bytes N] [--format ...]\n"
                 "  Deterministic DRBG output (for reproducibility/debugging).\n";
    return a.has("help") ? 0 : 1;
  }
  securekg::keygen::DrbgKind kind = securekg::keygen::DrbgKind::HmacSha256;
  if (a.has("drbg") && !securekg::keygen::parse_drbg_kind(a.get("drbg"), kind)) {
    std::cerr << "error: unknown DRBG '" << a.get("drbg") << "'\n";
    return 1;
  }
  Bytes entropy = securekg::util::from_hex(a.get("entropy"));
  Bytes nonce = a.has("nonce") ? securekg::util::from_hex(a.get("nonce")) : Bytes{};
  Bytes perso = a.has("perso") ? securekg::util::from_hex(a.get("perso")) : Bytes{};
  std::size_t bytes = static_cast<std::size_t>(a.get_long("bytes", 32));

  securekg::keygen::OutputFormat fmt = securekg::keygen::OutputFormat::Hex;
  if (a.has("format") && !securekg::keygen::parse_format(a.get("format"), fmt)) {
    std::cerr << "error: unknown format '" << a.get("format") << "'\n";
    return 1;
  }
  try {
    auto rng = securekg::keygen::Csprng::from_seed(kind, entropy, nonce, perso);
    Bytes out = rng.random_bytes(bytes);
    std::cout << securekg::keygen::format_key(out, fmt) << "\n";
  } catch (const std::exception& ex) {
    std::cerr << "error: " << ex.what() << "\n";
    return 1;
  }
  return 0;
}

int cmd_selftest() {
  auto report = securekg::run_self_tests();
  std::string last_std;
  for (const auto& c : report.cases) {
    if (c.standard != last_std) {
      std::cout << "\n[" << c.standard << "]\n";
      last_std = c.standard;
    }
    std::printf("  %-32s %s\n", c.name.c_str(), c.passed ? "PASS" : "FAIL");
  }
  std::cout << "\n" << report.passed << "/"
            << (report.passed + report.failed) << " known-answer tests passed.\n";
  return report.all_passed ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    print_usage();
    return 1;
  }
  std::string cmd = argv[1];
  Args a = parse_args(argc, argv, 2);

  if (cmd == "keygen") return cmd_keygen(a);
  if (cmd == "derive") return cmd_derive(a);
  if (cmd == "test") return cmd_test(a);
  if (cmd == "entropy") return cmd_entropy(a);
  if (cmd == "drbg") return cmd_drbg(a);
  if (cmd == "selftest") return cmd_selftest();
  if (cmd == "version" || cmd == "--version") {
    std::cout << "securekg " << kVersion << " (OS entropy backend: "
              << securekg::entropy::os_backend() << ")\n";
    return 0;
  }
  if (cmd == "help" || cmd == "--help" || cmd == "-h") {
    print_usage();
    return 0;
  }
  std::cerr << "error: unknown command '" << cmd << "'\n\n";
  print_usage();
  return 1;
}
