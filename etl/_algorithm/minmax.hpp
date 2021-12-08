/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_MINMAX_HPP
#define TETL_ALGORITHM_MINMAX_HPP

#include "etl/_functional/less.hpp"
#include "etl/_utility/pair.hpp"

namespace etl {

/// \brief Returns the lowest and the greatest of the given values.
/// \group minmax
/// \module Algorithm
template <typename T, typename Compare>
[[nodiscard]] constexpr auto minmax(T const& a, T const& b, Compare comp) -> pair<T const&, T const&>
{
    using return_type = pair<T const&, T const&>;
    return comp(b, a) ? return_type(b, a) : return_type(a, b);
}

/// \brief Returns the lowest and the greatest of the given values.
/// \group minmax
/// \module Algorithm
template <typename T>
[[nodiscard]] constexpr auto minmax(T const& a, T const& b) -> pair<T const&, T const&>
{
    return minmax(a, b, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_MINMAX_HPP