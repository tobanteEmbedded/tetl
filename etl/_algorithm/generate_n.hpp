/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_GENERATE_N_HPP
#define TETL_ALGORITHM_GENERATE_N_HPP

namespace etl {

/// \brief Assigns values, generated by given function object `g`, to the first
/// count elements in the range beginning at `first`, if `count > 0`. Does
/// nothing otherwise.
///
/// \param first The range of elements to generate.
/// \param count Number of the elements to generate.
/// \param g Generator function object that will be called.
///
/// https://en.cppreference.com/w/cpp/algorithm/generate_n
///
/// \module Algorithm
template <typename OutputIt, typename SizeT, typename Generator>
constexpr auto generate_n(OutputIt first, SizeT count, Generator g) -> OutputIt
{
    for (; count > 0; ++first, --count) { *first = g(); }
    return first;
}

} // namespace etl

#endif // TETL_ALGORITHM_GENERATE_N_HPP