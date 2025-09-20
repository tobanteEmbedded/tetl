// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_FUNCTIONAL_LOGICAL_OR_HPP
#define TETL_FUNCTIONAL_LOGICAL_OR_HPP

#include <etl/_utility/forward.hpp>

namespace etl {

/// \brief Function object for performing logical OR (logical disjunction).
/// Effectively calls operator|| on type T.
/// https://en.cppreference.com/w/cpp/utility/functional/logical_or
template <typename T = void>
struct logical_or {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> bool
    {
        return lhs or rhs;
    }
};

template <>
struct logical_or<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto
    operator()(T&& lhs, U&& rhs) const noexcept(noexcept(etl::forward<T>(lhs) or etl::forward<U>(rhs)))
        -> decltype(etl::forward<T>(lhs) or etl::forward<U>(rhs))
    {
        return etl::forward<T>(lhs) or etl::forward<U>(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_LOGICAL_OR_HPP
