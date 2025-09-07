// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_FUNCTIONAL_MODULUS_HPP
#define TETL_FUNCTIONAL_MODULUS_HPP

#include <etl/_utility/forward.hpp>

namespace etl {

/// \brief Function object for computing remainders of divisions. Implements
/// operator% for type T.
/// https://en.cppreference.com/w/cpp/utility/functional/modulus
template <typename T = void>
struct modulus {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
    {
        return static_cast<T>(lhs % rhs);
    }
};

template <>
struct modulus<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto
    operator()(T&& lhs, U&& rhs) const noexcept(noexcept(etl::forward<T>(lhs) % etl::forward<U>(rhs)))
        -> decltype(etl::forward<T>(lhs) % etl::forward<U>(rhs))
    {
        return etl::forward<T>(lhs) % etl::forward<U>(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_MODULUS_HPP
