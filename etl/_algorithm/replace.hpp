/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_REPLACE_HPP
#define TETL_ALGORITHM_REPLACE_HPP

#include "etl/_algorithm/replace_if.hpp"

namespace etl {

/// \brief Replaces all elements satisfying specific criteria with new_value in
/// the range [first, last). Replaces all elements that are equal to
/// old_value.
/// \group replace
/// \module Algorithm
template <typename ForwardIt, typename T>
constexpr auto replace(ForwardIt first, ForwardIt last, T const& oldValue, T const& newValue) -> void
{
    auto predicate = [&oldValue](auto const& item) { return item == oldValue; };
    replace_if(first, last, predicate, newValue);
}

} // namespace etl

#endif // TETL_ALGORITHM_REPLACE_HPP