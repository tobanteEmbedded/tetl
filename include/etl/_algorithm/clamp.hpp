// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_ALGORITHM_CLAMP_HPP
#define TETL_ALGORITHM_CLAMP_HPP

#include <etl/_functional/less.hpp>

namespace etl {

/// \ingroup algorithm
/// @{

/// \brief If v compares less than lo, returns lo; otherwise if hi compares less
/// than v, returns hi; otherwise returns v. Uses operator< to compare the
/// values.
template <typename Type, typename Compare>
[[nodiscard]] constexpr auto clamp(Type const& v, Type const& lo, Type const& hi, Compare comp) -> Type const&
{
    return comp(v, lo) ? lo : comp(hi, v) ? hi : v;
}

template <typename Type>
[[nodiscard]] constexpr auto clamp(Type const& v, Type const& lo, Type const& hi) noexcept -> Type const&
{
    return etl::clamp(v, lo, hi, etl::less<Type>());
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_CLAMP_HPP
