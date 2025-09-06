// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch
#ifndef TETL_NUMERIC_GCD_HPP
#define TETL_NUMERIC_GCD_HPP

#include <etl/_type_traits/common_type.hpp>

namespace etl {

/// \brief Computes the greatest common divisor of the integers m and n.
///
/// \returns If both m and n are zero, returns zero. Otherwise, returns the
/// greatest common divisor of |m| and |n|.
///
/// \ingroup numeric
template <typename M, typename N>
[[nodiscard]] constexpr auto gcd(M m, N n) noexcept -> etl::common_type_t<M, N>
{
    using R = etl::common_type_t<M, N>;

    R a = static_cast<R>(m);
    R b = static_cast<R>(n);

    while (b != 0) {
        auto const r = static_cast<R>(a % b);
        a            = b;
        b            = r;
    }

    return a; // If both inputs were 0, this is 0.
}

} // namespace etl

#endif // TETL_NUMERIC_GCD_HPP
