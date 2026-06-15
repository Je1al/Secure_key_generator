#include "securekg/keygen/key.h"

#include "securekg/util/bytes.h"

namespace securekg::keygen {

bool parse_format(const std::string& s, OutputFormat& out) {
  if (s == "hex") {
    out = OutputFormat::Hex;
  } else if (s == "base64" || s == "b64") {
    out = OutputFormat::Base64;
  } else if (s == "binary" || s == "bin") {
    out = OutputFormat::Binary;
  } else if (s == "raw") {
    out = OutputFormat::Raw;
  } else if (s == "c" || s == "c-array" || s == "carray") {
    out = OutputFormat::CArray;
  } else {
    return false;
  }
  return true;
}

const char* to_string(OutputFormat fmt) {
  switch (fmt) {
    case OutputFormat::Hex: return "hex";
    case OutputFormat::Base64: return "base64";
    case OutputFormat::Binary: return "binary";
    case OutputFormat::Raw: return "raw";
    case OutputFormat::CArray: return "c-array";
  }
  return "hex";
}

std::string format_key(const Bytes& key, OutputFormat fmt,
                       const std::string& c_array_name) {
  switch (fmt) {
    case OutputFormat::Hex:
      return util::to_hex(key);
    case OutputFormat::Base64:
      return util::to_base64(key);
    case OutputFormat::Binary:
      return util::to_binary(key);
    case OutputFormat::Raw:
      return std::string(key.begin(), key.end());
    case OutputFormat::CArray:
      return util::to_c_array(key, c_array_name);
  }
  return util::to_hex(key);
}

}  // namespace securekg::keygen
