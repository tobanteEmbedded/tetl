// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_MINMAX_HPP
#define TETL_ALGORITHM_MINMAX_HPP

#include <etl/_functional/less.hpp>
#include <etl/_utility/pair.hpp>

namespace etl {

/// \brief Returns the lowest and the greatest of the given values.
/// \ingroup algorithm
template <typename T, typename Compare>
[[nodiscard]] constexpr auto minmax(T const& a, T const& b, Compare comp) -> pair<T const&, T const&>
{
    using return_type = pair<T const&, T const&>;
    return comp(b, a) ? return_type(b, a) : return_type(a, b);
}

/// \brief Returns the lowest and the greatest of the given values.
/// \ingroup algorithm
template <typename T>
[[nodiscard]] constexpr auto minmax(T const& a, T const& b) -> pair<T const&, T const&>
{
    return etl::minmax(a, b, etl::less());
}

} // namespace etl

#endif // TETL_ALGORITHM_MINMAX_HPP
