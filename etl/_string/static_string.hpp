/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_STRING_STATIC_STRING_HPP
#define TETL_STRING_STATIC_STRING_HPP

#include "etl/_string/basic_static_string.hpp"

namespace etl {

/// Typedef for a basic_static_string using 'char'
template <etl::size_t Capacity>
using static_string = basic_static_string<char, Capacity>;

} // namespace etl

#endif // TETL_STRING_STATIC_STRING_HPP