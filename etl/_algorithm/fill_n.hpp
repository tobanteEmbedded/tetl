/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_FILL_N_HPP
#define TETL_ALGORITHM_FILL_N_HPP

namespace etl {

/// \brief Assigns the given value to the first count elements in the range
/// beginning at `first` if `count > 0`. Does nothing otherwise.
///
/// \returns Iterator one past the last element assigned if `count > 0`, `first`
/// otherwise.
///
/// \module Algorithm
template <typename OutputIt, typename Size, typename T>
constexpr auto fill_n(OutputIt first, Size count, T const& value) -> OutputIt
{
    for (auto i = Size { 0 }; i < count; ++i) {
        *first = value;
        ++first;
    }
    return first;
}

} // namespace etl

#endif // TETL_ALGORITHM_FILL_N_HPP