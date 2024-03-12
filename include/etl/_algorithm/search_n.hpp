// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_SEARCH_N_HPP
#define TETL_ALGORITHM_SEARCH_N_HPP

namespace etl {

/// \brief Searches the range `[first, last)` for the first sequence of count
/// identical elements, each equal to the given value.
template <typename ForwardIt, typename Size, typename ValueT, typename Predicate>
[[nodiscard]] constexpr auto
search_n(ForwardIt first, ForwardIt last, Size count, ValueT const& value, Predicate pred) -> ForwardIt
{
    if (count <= Size{}) {
        return first;
    }

    auto localCounter = Size{};
    ForwardIt found   = nullptr;

    for (; first != last; ++first) {
        if (pred(*first, value)) {
            localCounter++;
            if (found == nullptr) {
                found = first;
            }
        } else {
            localCounter = 0;
        }

        if (localCounter == count) {
            return found;
        }
    }

    return last;
}

template <typename ForwardIt, typename Size, typename ValueT>
[[nodiscard]] constexpr auto search_n(ForwardIt first, ForwardIt last, Size count, ValueT const& value) -> ForwardIt
{
    auto const eq = [](auto const& l, auto const& r) { return l == r; };
    return search_n(first, last, count, value, eq);
}

} // namespace etl

#endif // TETL_ALGORITHM_SEARCH_N_HPP
