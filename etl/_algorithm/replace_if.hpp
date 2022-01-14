/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_REPLACE_IF_HPP
#define TETL_ALGORITHM_REPLACE_IF_HPP

namespace etl {

/// \brief Replaces all elements satisfying specific criteria with new_value in
/// the range [first, last). Replaces all elements for which predicate p
/// returns true.
template <typename ForwardIt, typename Predicate, typename T>
constexpr auto replace_if(ForwardIt first, ForwardIt last, Predicate p, T const& newValue) -> void
{
    for (; first != last; ++first) {
        if (p(*first)) { *first = newValue; }
    }
}

} // namespace etl

#endif // TETL_ALGORITHM_REPLACE_IF_HPP