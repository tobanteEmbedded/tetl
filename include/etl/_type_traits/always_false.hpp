/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_ALWAYS_FALSE_HPP
#define TETL_TYPE_TRAITS_ALWAYS_FALSE_HPP

namespace etl {

template <typename... T>
constexpr bool always_false = false;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ALWAYS_FALSE_HPP
