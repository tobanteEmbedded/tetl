/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_FILL_HPP
#define TETL_ALGORITHM_FILL_HPP

namespace etl {

/// \brief Assigns the given value to the elements in the range `[first, last)`.
template <typename ForwardIt, typename T>
constexpr auto fill(ForwardIt first, ForwardIt last, T const& value) -> void
{
    for (; first != last; ++first) { *first = value; }
}

} // namespace etl

#endif // TETL_ALGORITHM_FILL_HPP
