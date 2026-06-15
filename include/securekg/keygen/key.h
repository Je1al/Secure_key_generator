#ifndef SECUREKG_KEYGEN_KEY_H_
#define SECUREKG_KEYGEN_KEY_H_

#include <cstdint>
#include <string>
#include <vector>

namespace securekg::keygen {

using Bytes = std::vector<std::uint8_t>;

enum class OutputFormat { Hex, Base64, Binary, Raw, CArray };

bool parse_format(const std::string& s, OutputFormat& out);
const char* to_string(OutputFormat fmt);

// Render key bytes in the requested textual format. For OutputFormat::Raw the
// returned string holds the raw bytes verbatim (suitable for writing to a file
// or piping); all other formats are printable text.
std::string format_key(const Bytes& key, OutputFormat fmt,
                       const std::string& c_array_name = "key");

}  // namespace securekg::keygen

#endif  // SECUREKG_KEYGEN_KEY_H_
