// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_STRING_VIEW_STRING_VIEW_HPP
#define TETL_STRING_VIEW_STRING_VIEW_HPP

#include <etl/_string_view/basic_string_view.hpp>

namespace etl {

/// \brief Typedefs for common character type
using string_view = basic_string_view<char, etl::char_traits<char>>;

} // namespace etl

#endif // TETL_STRING_VIEW_STRING_VIEW_HPP
