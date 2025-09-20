// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_INTEGRAL_CONSTANT_HPP
#define TETL_TYPE_TRAITS_INTEGRAL_CONSTANT_HPP

namespace etl {

/// \ingroup type_traits
template <typename Type, Type Val>
struct integral_constant {
    static constexpr Type value = Val;
    using value_type            = Type;
    using type                  = integral_constant<Type, Val>;

    constexpr operator value_type() const noexcept
    {
        return value;
    }

    constexpr auto operator()() const noexcept -> value_type
    {
        return value;
    }
};

/// \relates integral_constant
/// \ingroup type_traits
template <typename Rhs, Rhs R, typename Lhs, Lhs L>
[[nodiscard]] constexpr auto operator+(integral_constant<Rhs, R> /*l*/, integral_constant<Lhs, L> /*r*/)
    -> integral_constant<decltype(L + R), L + R>
{
    return {};
}

/// \relates integral_constant
/// \ingroup type_traits
template <typename Rhs, Rhs R, typename Lhs, Lhs L>
[[nodiscard]] constexpr auto operator==(integral_constant<Rhs, R> /*l*/, integral_constant<Lhs, L> /*r*/)
    -> integral_constant<bool, L == R>
{
    return {};
}

/// \relates integral_constant
/// \ingroup type_traits
template <typename Rhs, Rhs R, typename Lhs, Lhs L>
[[nodiscard]] constexpr auto operator!=(integral_constant<Rhs, R> /*l*/, integral_constant<Lhs, L> /*r*/)
    -> integral_constant<bool, L != R>
{
    return {};
}

} // namespace etl

#endif // TETL_TYPE_TRAITS_INTEGRAL_CONSTANT_HPP
