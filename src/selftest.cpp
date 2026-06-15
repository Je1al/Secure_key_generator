#include "securekg/selftest.h"

#include <string>

#include "securekg/crypto/aes.h"
#include "securekg/crypto/hmac_sha256.h"
#include "securekg/crypto/kdf.h"
#include "securekg/crypto/sha256.h"
#include "securekg/drbg/ctr_drbg.h"
#include "securekg/drbg/hash_drbg.h"
#include "securekg/drbg/hmac_drbg.h"
#include "securekg/util/bytes.h"

namespace securekg {
namespace {

using util::Bytes;
using util::from_hex;
using util::to_hex;

struct Builder {
  SelfTestReport report;
  void add(const std::string& name, const std::string& standard,
           const std::string& got, const std::string& expected) {
    bool ok = (got == expected);
    report.cases.push_back({name, standard, ok});
    if (ok)
      ++report.passed;
    else {
      ++report.failed;
      report.all_passed = false;
    }
  }
};

std::string sha256_hex(const Bytes& d) {
  auto h = crypto::Sha256::hash(d);
  return to_hex(h.data(), h.size());
}

}  // namespace

SelfTestReport run_self_tests() {
  Builder b;

  // --- SHA-256 (FIPS 180-4) ---
  b.add("SHA-256(\"abc\")", "FIPS 180-4",
        sha256_hex({'a', 'b', 'c'}),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  b.add("SHA-256(\"\")", "FIPS 180-4", sha256_hex({}),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  {
    Bytes million(1000000, 'a');
    b.add("SHA-256(1e6 x 'a')", "FIPS 180-4", sha256_hex(million),
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  }

  // --- HMAC-SHA256 (RFC 4231) ---
  {
    Bytes key(20, 0x0b);
    Bytes data = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
    auto m = crypto::HmacSha256::mac(key, data);
    b.add("HMAC-SHA256 case 1", "RFC 4231", to_hex(m.data(), m.size()),
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  }
  {
    Bytes key = {'J', 'e', 'f', 'e'};
    std::string s = "what do ya want for nothing?";
    Bytes data(s.begin(), s.end());
    auto m = crypto::HmacSha256::mac(key, data);
    b.add("HMAC-SHA256 case 2", "RFC 4231", to_hex(m.data(), m.size()),
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  }

  // --- HKDF-SHA256 (RFC 5869, Test Case 1) ---
  {
    Bytes ikm(22, 0x0b);
    Bytes salt = from_hex("000102030405060708090a0b0c");
    Bytes info = from_hex("f0f1f2f3f4f5f6f7f8f9");
    Bytes prk = crypto::hkdf_extract(salt, ikm);
    Bytes okm = crypto::hkdf_expand(prk, info, 42);
    b.add("HKDF-SHA256 PRK", "RFC 5869", to_hex(prk),
          "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    b.add("HKDF-SHA256 OKM", "RFC 5869", to_hex(okm),
          "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
          "34007208d5b887185865");
  }

  // --- PBKDF2-HMAC-SHA256 (RFC 8018 / RFC 7914 test set) ---
  {
    Bytes pw = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    Bytes salt = {'s', 'a', 'l', 't'};
    b.add("PBKDF2-HMAC-SHA256 c=1", "RFC 8018",
          to_hex(crypto::pbkdf2_hmac_sha256(pw, salt, 1, 32)),
          "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    b.add("PBKDF2-HMAC-SHA256 c=4096", "RFC 8018",
          to_hex(crypto::pbkdf2_hmac_sha256(pw, salt, 4096, 32)),
          "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
  }

  // --- AES (FIPS 197 Appendix C) ---
  {
    Bytes key = from_hex("000102030405060708090a0b0c0d0e0f");
    Bytes pt = from_hex("00112233445566778899aabbccddeeff");
    std::uint8_t ct[16];
    crypto::Aes aes(key.data(), key.size());
    aes.encrypt_block(pt.data(), ct);
    b.add("AES-128 block encrypt", "FIPS 197", to_hex(ct, 16),
          "69c4e0d86a7b0430d8cdb78070b4c55a");
  }
  {
    Bytes key = from_hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    Bytes pt = from_hex("00112233445566778899aabbccddeeff");
    std::uint8_t ct[16];
    crypto::Aes aes(key.data(), key.size());
    aes.encrypt_block(pt.data(), ct);
    b.add("AES-256 block encrypt", "FIPS 197", to_hex(ct, 16),
          "8ea2b7ca516745bfeafc49904b496089");
  }

  // --- HMAC-DRBG SHA-256 (NIST SP 800-90A CAVP, no reseed, PR=False) ---
  {
    Bytes e = from_hex(
        "ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488");
    Bytes n = from_hex("659ba96c601dc69fc902940805ec0ca8");
    drbg::HmacDrbg d(e, n);
    d.generate(128);
    auto r = d.generate(128);
    b.add("HMAC-DRBG (no perso/addin)", "NIST SP 800-90A CAVP", to_hex(r),
          "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89"
          "d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1"
          "07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668"
          "961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8");
  }
  {
    Bytes e = from_hex(
        "5d3286bc53a258a53ba781e2c4dcd79a790e43bbe0e89fb3eed39086be34174b");
    Bytes n = from_hex("c5422294b7318952ace7055ab7570abf");
    Bytes perso = from_hex(
        "2dba094d008e150d51c4135bb2f03dcde9cbf3468a12908a1b025c120c985b9d");
    Bytes a1 = from_hex(
        "793a7ef8f6f0482beac542bb785c10f8b7b406a4de92667ab168ecc2cf7573c6");
    Bytes a2 = from_hex(
        "2238cdb4e23d629fe0c2a83dd8d5144ce1a6229ef41dabe2a99ff722e510b530");
    drbg::HmacDrbg d(e, n, perso);
    d.generate(128, a1);
    auto r = d.generate(128, a2);
    b.add("HMAC-DRBG (perso+addin)", "NIST SP 800-90A CAVP", to_hex(r),
          "d04678198ae7e1aeb435b45291458ffde0891560748b43330eaf866b5a6385e7"
          "4c6fa5a5a44bdb284d436e98d244018d6acedcdfa2e9f499d8089e4db86ae89a"
          "6ab2d19cb705e2f048f97fb597f04106a1fa6a1416ad3d859118e079a0c319eb"
          "95686f4cbcce3b5101c7a0b010ef029c4ef6d06cdfac97efb9773891688c37cf");
  }

  // --- Hash-DRBG SHA-256 (NIST SP 800-90A CAVP) ---
  {
    Bytes e = from_hex(
        "a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb");
    Bytes n = from_hex("8581f9317517276e06e9607ddbcbcc2e");
    drbg::HashDrbg d(e, n);
    d.generate(128);
    auto r = d.generate(128);
    b.add("Hash-DRBG (no perso/addin)", "NIST SP 800-90A CAVP", to_hex(r),
          "d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80d"
          "aaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febd"
          "c343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51c"
          "cde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df");
  }
  {
    Bytes e = from_hex(
        "68c43a008fe46a823d260a9d7fa388fb9e401f0197e7e758a744b4babb3f4651");
    Bytes n = from_hex("eb6825777856331884aaf3751b3e4006");
    Bytes perso = from_hex(
        "23ce0d32cbf2d26467f0d62acff1a3acbaa6d2746dc3ee7aa9d32c880788afc8");
    Bytes a1 = from_hex(
        "a31b9f13b58d4fa2f8d8ac42b62a207ff647339a146bd8b268b33d4aff57adbd");
    Bytes a2 = from_hex(
        "d34fc6504eca4b568193c75357b0d3821a48c77ff80d6dbd21c6cf045ff489cf");
    drbg::HashDrbg d(e, n, perso);
    d.generate(128, a1);
    auto r = d.generate(128, a2);
    b.add("Hash-DRBG (perso+addin)", "NIST SP 800-90A CAVP", to_hex(r),
          "abb4ecbacd4e8fa943c7221aed433861c3b203232657ec4c417d021f905d911d"
          "b1058ff1e11e272232482ec96bae7cb4efc135502dbe41724077077f6de79b71"
          "3670c385d04644e1281c3e582e0016255abbe5f8c06d0de57160559f0c08f7fb"
          "5be3563c649966190f8d3261364447537de2c7371c6e8c308933d27145bf90ab");
  }

  // --- CTR-DRBG AES-256 no df (NIST SP 800-90A CAVP) ---
  {
    Bytes e = from_hex(
        "df5d73faa468649edda33b5cca79b0b05600419ccb7a879ddfec9db32ee494e5"
        "531b51de16a30f769262474c73bec010");
    drbg::CtrDrbg d(e);
    d.generate(64);
    auto r = d.generate(64);
    b.add("CTR-DRBG (no perso/addin)", "NIST SP 800-90A CAVP", to_hex(r),
          "d1c07cd95af8a7f11012c84ce48bb8cb87189e99d40fccb1771c619bdf82ab22"
          "80b1dc2f2581f39164f7ac0c510494b3a43c41b7db17514c87b107ae793e01c5");
  }
  {
    Bytes e = from_hex(
        "0dd4d80062ecc0f359efbe7723020be9b88b550fe74088094069e7442839585"
        "6f63eed4f5b0e7d1e006f0eaff74f638c");
    Bytes perso = from_hex(
        "d2aa2ccd4bc6537e51f6550ab6d6294547bef3e971a7f128e4436f957de9982c"
        "93ee22110b0e40ab33a7d3dfa22f599d");
    Bytes a1 = from_hex(
        "0b081bab6c74d86b4a010e2ded99d14e0c9838f7c3d69afd64f1b66377d95cdc"
        "b7f6ec5358e3516034c3339ced7e1638");
    Bytes a2 = from_hex(
        "ca818f938ae0c7f4f507e4cfec10e7baf51fe34b89a502f754d2d2be7395120f"
        "e1fb013c67ac2500b3d17b735da09a6e");
    drbg::CtrDrbg d(e, perso);
    d.generate(64, a1);
    auto r = d.generate(64, a2);
    b.add("CTR-DRBG (perso+addin)", "NIST SP 800-90A CAVP", to_hex(r),
          "6808268b13e236f642c06deba2494496e7003c937ebf6f7cb7c92104ea090f18"
          "484aa075560d7844a06eb559948c93b26ae40f2db98ecb53ad593eb4c78f82b1");
  }

  return b.report;
}

}  // namespace securekg
