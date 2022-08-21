/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_ROTL_HPP
#define TETL_BIT_ROTL_HPP

#include "etl/_bit/bit_uint.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/enable_if.hpp"

namespace etl {

/// \brief Computes the result of bitwise left-rotating the value of x by s
/// positions. This operation is also known as a left circular shift.
template <typename T, enable_if_t<detail::bit_uint_v<T>, int> = 0>
constexpr auto rotl(T t, int s) noexcept -> T
{
    auto const c = static_cast<unsigned>(s);
    auto const d = static_cast<unsigned>(etl::numeric_limits<T>::digits);
    if ((c % d) == 0U) { return t; }
    return static_cast<T>((t << (c % d)) | (t >> (d - (c % d))));
}

} // namespace etl

#endif // TETL_BIT_ROTL_HPP
