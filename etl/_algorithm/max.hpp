/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_MAX_HPP
#define TETL_ALGORITHM_MAX_HPP

namespace etl {

/// \brief Returns the greater of a and b.
/// \group max
/// \module Algorithm
template <typename Type>
[[nodiscard]] constexpr auto max(Type const& a, Type const& b) noexcept
    -> Type const&
{
    return (a < b) ? b : a;
}

/// \brief Returns the greater of a and b, using a compare function.
/// \group max
/// \module Algorithm
template <typename Type, typename Compare>
[[nodiscard]] constexpr auto max(
    Type const& a, Type const& b, Compare comp) noexcept -> Type const&
{
    return (comp(a, b)) ? b : a;
}

} // namespace etl

#endif // TETL_ALGORITHM_MAX_HPP