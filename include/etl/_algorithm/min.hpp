// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_MIN_HPP
#define TETL_ALGORITHM_MIN_HPP

namespace etl {

/// \brief Returns the smaller of a and b.
/// \ingroup algorithm
template <typename Type>
[[nodiscard]] constexpr auto min(Type const& a, Type const& b) noexcept -> Type const&
{
    return (b < a) ? b : a;
}

/// \brief Returns the smaller of a and b, using a compare function.
/// \ingroup algorithm
template <typename Type, typename Compare>
[[nodiscard]] constexpr auto min(Type const& a, Type const& b, Compare comp) noexcept -> Type const&
{
    return (comp(b, a)) ? b : a;
}

} // namespace etl

#endif // TETL_ALGORITHM_MIN_HPP
