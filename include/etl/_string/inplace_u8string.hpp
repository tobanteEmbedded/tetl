// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_STRING_INPLACE_U8STRING_HPP
#define TETL_STRING_INPLACE_U8STRING_HPP

#include <etl/_string/basic_inplace_string.hpp>

namespace etl {

/// Typedef for a basic_inplace_string using 'char8_t'
template <etl::size_t Capacity>
using inplace_u8string = basic_inplace_string<char8_t, Capacity>;

} // namespace etl

#endif // TETL_STRING_INPLACE_U8STRING_HPP
