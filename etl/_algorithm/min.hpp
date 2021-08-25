/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_MIN_HPP
#define TETL_ALGORITHM_MIN_HPP

namespace etl {

/// \brief Returns the smaller of a and b.
/// \group min
/// \module Algorithm
template <typename Type>
[[nodiscard]] constexpr auto min(Type const& a, Type const& b) noexcept
    -> Type const&
{
    return (b < a) ? b : a;
}

/// \brief Returns the smaller of a and b, using a compare function.
/// \group min
/// \module Algorithm
template <typename Type, typename Compare>
[[nodiscard]] constexpr auto min(
    Type const& a, Type const& b, Compare comp) noexcept -> Type const&
{
    return (comp(b, a)) ? b : a;
}

} // namespace etl

#endif // TETL_ALGORITHM_MIN_HPP