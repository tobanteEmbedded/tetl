/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_ROTR_HPP
#define TETL_BIT_ROTR_HPP

#include "etl/_bit/bit_uint.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/enable_if.hpp"

namespace etl {

/// \brief Computes the result of bitwise right-rotating the value of x by s
/// positions. This operation is also known as a right circular shift.
template <typename T, enable_if_t<detail::bit_uint_v<T>, int> = 0>
constexpr auto rotr(T t, int s) noexcept -> T
{
    auto const cnt    = static_cast<unsigned>(s);
    auto const digits = static_cast<unsigned>(etl::numeric_limits<T>::digits);
    if ((cnt % digits) == 0) { return t; }
    return (t >> (cnt % digits)) | (t << (digits - (cnt % digits)));
}

} // namespace etl

#endif // TETL_BIT_ROTR_HPP
