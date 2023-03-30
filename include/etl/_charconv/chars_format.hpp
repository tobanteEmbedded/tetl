// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHARCONV_CHARS_FORMAT_HPP
#define TETL_CHARCONV_CHARS_FORMAT_HPP

#include <etl/_cstdint/uint_t.hpp>

namespace etl {

/// \brief A BitmaskType used to specify floating-point formatting for to_chars
/// and from_chars.
enum struct chars_format : etl::uint8_t {
    scientific = 0x1,
    fixed      = 0x2,
    hex        = 0x4,
    general    = fixed | scientific,
};

} // namespace etl

#endif // TETL_CHARCONV_CHARS_FORMAT_HPP
