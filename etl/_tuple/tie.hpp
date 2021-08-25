/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TUPLE_TIE_HPP
#define TETL_TUPLE_TIE_HPP

#include "etl/_tuple/tuple.hpp"

namespace etl {

template <typename... Args>
constexpr auto tie(Args&... args) noexcept -> tuple<Args&...>
{
    return { args... };
}

} // namespace etl

#endif // TETL_TUPLE_TIE_HPP
