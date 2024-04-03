// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_REPLACE_IF_HPP
#define TETL_ALGORITHM_REPLACE_IF_HPP

namespace etl {

/// \brief Replaces all elements satisfying specific criteria with new_value in
/// the range [first, last). Replaces all elements for which predicate p
/// returns true.
/// \ingroup algorithm
template <typename ForwardIt, typename Predicate, typename T>
constexpr auto replace_if(ForwardIt first, ForwardIt last, Predicate p, T const& newValue) -> void
{
    for (; first != last; ++first) {
        if (p(*first)) {
            *first = newValue;
        }
    }
}

} // namespace etl

#endif // TETL_ALGORITHM_REPLACE_IF_HPP
