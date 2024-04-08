// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_STRING_STATIC_WSTRING_HPP
#define TETL_STRING_STATIC_WSTRING_HPP

#include <etl/_string/basic_inplace_string.hpp>

namespace etl {

/// Typedef for a basic_inplace_string using 'wchar_t'
template <etl::size_t Capacity>
using inplace_wstring = basic_inplace_string<wchar_t, Capacity>;

} // namespace etl

#endif // TETL_STRING_STATIC_WSTRING_HPP
