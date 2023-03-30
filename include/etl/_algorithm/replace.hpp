// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_REPLACE_HPP
#define TETL_ALGORITHM_REPLACE_HPP

#include "etl/_algorithm/replace_if.hpp"

namespace etl {

/// \brief Replaces all elements satisfying specific criteria with new_value in
/// the range [first, last). Replaces all elements that are equal to
/// old_value.
template <typename ForwardIt, typename T>
constexpr auto replace(ForwardIt first, ForwardIt last, T const& oldValue, T const& newValue) -> void
{
    auto predicate = [&oldValue](auto const& item) { return item == oldValue; };
    replace_if(first, last, predicate, newValue);
}

} // namespace etl

#endif // TETL_ALGORITHM_REPLACE_HPP
