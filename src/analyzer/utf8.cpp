#include "utf8.hpp"

#include <cstddef>
#include <string_view>

namespace noleax::analyzer::detail {

bool is_valid_utf8(std::string_view value) noexcept {
  const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
  std::size_t index = 0U;
  while (index < value.size()) {
    const unsigned char first = bytes[index];
    if (first <= 0x7fU) {
      ++index;
      continue;
    }

    std::size_t continuation_count = 0U;
    unsigned char second_minimum = 0x80U;
    unsigned char second_maximum = 0xbfU;
    if (first >= 0xc2U && first <= 0xdfU) {
      continuation_count = 1U;
    } else if (first >= 0xe0U && first <= 0xefU) {
      continuation_count = 2U;
      if (first == 0xe0U) {
        second_minimum = 0xa0U;
      } else if (first == 0xedU) {
        second_maximum = 0x9fU;
      }
    } else if (first >= 0xf0U && first <= 0xf4U) {
      continuation_count = 3U;
      if (first == 0xf0U) {
        second_minimum = 0x90U;
      } else if (first == 0xf4U) {
        second_maximum = 0x8fU;
      }
    } else {
      return false;
    }

    if (continuation_count > value.size() - index - 1U) {
      return false;
    }
    const unsigned char second = bytes[index + 1U];
    if (second < second_minimum || second > second_maximum) {
      return false;
    }
    for (std::size_t offset = 2U; offset <= continuation_count; ++offset) {
      if (bytes[index + offset] < 0x80U || bytes[index + offset] > 0xbfU) {
        return false;
      }
    }
    index += continuation_count + 1U;
  }
  return true;
}

}  // namespace noleax::analyzer::detail
