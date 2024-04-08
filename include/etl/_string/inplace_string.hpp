// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_STRING_STATIC_STRING_HPP
#define TETL_STRING_STATIC_STRING_HPP

#include <etl/_string/basic_inplace_string.hpp>

namespace etl {

/// Typedef for a basic_inplace_string using 'char'
template <etl::size_t Capacity>
using inplace_string = basic_inplace_string<char, Capacity>;

} // namespace etl

#endif // TETL_STRING_STATIC_STRING_HPP
