// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_FIND_END_HPP
#define TETL_ALGORITHM_FIND_END_HPP

#include <etl/_algorithm/search.hpp>
#include <etl/_functional/equal_to.hpp>

namespace etl {

/// \brief Searches for the last occurrence of the sequence [sFirst, sLast) in
/// the range `[first, last)`. Elements are compared using the given binary
/// predicate p.
/// \param first The range of elements to examine
/// \param last The range of elements to examine
/// \param sFirst The range of elements to search for
/// \param sLast The range of elements to search for
/// \param p Binary predicate
/// \returns Iterator to the beginning of last occurrence of the sequence
/// [sFirst, sLast) in range `[first, last)`. If [sFirst, sLast) is empty or if
/// no such sequence is found, last is returned.
/// \ingroup algorithm
template <typename ForwardIt1, typename ForwardIt2, typename Predicate>
[[nodiscard]] constexpr auto
find_end(ForwardIt1 first, ForwardIt1 last, ForwardIt2 sFirst, ForwardIt2 sLast, Predicate p) -> ForwardIt1
{
    if (sFirst == sLast) {
        return last;
    }
    auto result = last;
    while (true) {
        auto newResult = etl::search(first, last, sFirst, sLast, p);
        if (newResult == last) {
            break;
        }
        result = newResult;
        first  = result;
        ++first;
    }
    return result;
}

/// \ingroup algorithm
template <typename ForwardIt1, typename ForwardIt2>
[[nodiscard]] constexpr auto find_end(ForwardIt1 first, ForwardIt1 last, ForwardIt2 sFirst, ForwardIt2 sLast)
    -> ForwardIt1
{
    return etl::find_end(first, last, sFirst, sLast, etl::equal_to());
}

} // namespace etl

#endif // TETL_ALGORITHM_FIND_END_HPP
