/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHARCONV_CHARS_FORMAT_HPP
#define TETL_CHARCONV_CHARS_FORMAT_HPP

#include "etl/_cstdint/uint_t.hpp"

namespace etl {

/// \brief A BitmaskType used to specify floating-point formatting for to_chars
/// and from_chars.
/// \module Strings
enum struct chars_format : etl::uint8_t {
    scientific = 0x1,
    fixed      = 0x2,
    hex        = 0x4,
    general    = fixed | scientific
};

} // namespace etl

#endif // TETL_CHARCONV_CHARS_FORMAT_HPP