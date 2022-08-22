/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_STRING_VIEW_STRING_VIEW_HPP
#define TETL_STRING_VIEW_STRING_VIEW_HPP

#include "etl/_string_view/basic_string_view.hpp"

namespace etl {

/// \brief Typedefs for common character type
using string_view = basic_string_view<char, etl::char_traits<char>>;

} // namespace etl

#endif // TETL_STRING_VIEW_STRING_VIEW_HPP
