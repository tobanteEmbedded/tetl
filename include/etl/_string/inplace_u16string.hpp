// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_STRING_INPLACE_U16STRING_HPP
#define TETL_STRING_INPLACE_U16STRING_HPP

#include <etl/_string/basic_inplace_string.hpp>

namespace etl {

/// Typedef for a basic_inplace_string using 'char16_t'
template <etl::size_t Capacity>
using inplace_u16string = basic_inplace_string<char16_t, Capacity>;

} // namespace etl

#endif // TETL_STRING_INPLACE_U16STRING_HPP
