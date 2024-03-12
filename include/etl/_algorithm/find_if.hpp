// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_FIND_IF_HPP
#define TETL_ALGORITHM_FIND_IF_HPP

namespace etl {

/// \brief Searches for an element for which predicate p returns true
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param pred Unary predicate which returns ​true for the required element.
///
/// https://en.cppreference.com/w/cpp/algorithm/find
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto find_if(InputIt first, InputIt last, Predicate pred) noexcept -> InputIt
{
    for (; first != last; ++first) {
        if (pred(*first)) {
            return first;
        }
    }
    return last;
}

} // namespace etl

#endif // TETL_ALGORITHM_FIND_IF_HPP
