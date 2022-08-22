/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_COPY_IF_HPP
#define TETL_ALGORITHM_COPY_IF_HPP

namespace etl {

/// \ingroup algorithm-header
/// @{

/// \brief Copies the elements in the range, defined by `[first, last)`, to
/// another range beginning at destination.
/// \details Only copies the elements for which the predicate pred returns true.
/// The relative order of the elements that are copied is preserved. The
/// behavior is undefined if the source and the destination ranges overlap.
/// \returns Output iterator to the element in the destination range, one past
/// the last element copied.
template <typename InIt, typename OutIt, typename Pred>
constexpr auto copy_if(InIt first, InIt last, OutIt dFirst, Pred pred) -> OutIt
{
    while (first != last) {
        if (pred(*first)) { *dFirst++ = *first; }
        ++first;
    }
    return dFirst;
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_COPY_IF_HPP
