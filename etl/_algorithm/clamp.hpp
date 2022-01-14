/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_CLAMP_HPP
#define TETL_ALGORITHM_CLAMP_HPP

#include "etl/_cassert/macro.hpp"
#include "etl/_functional/less.hpp"

namespace etl {

/// \ingroup algorithm-header
/// @{

/// \brief If v compares less than lo, returns lo; otherwise if hi compares less
/// than v, returns hi; otherwise returns v. Uses operator< to compare the
/// values.
template <typename Type>
[[nodiscard]] constexpr auto clamp(Type const& v, Type const& lo, Type const& hi) noexcept -> Type const&
{
    return clamp(v, lo, hi, less<Type>());
}
template <typename Type, typename Compare>
[[nodiscard]] constexpr auto clamp(Type const& v, Type const& lo, Type const& hi, Compare comp) -> Type const&
{
    TETL_ASSERT(!comp(hi, lo));
    return comp(v, lo) ? lo : comp(hi, v) ? hi : v;
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_CLAMP_HPP