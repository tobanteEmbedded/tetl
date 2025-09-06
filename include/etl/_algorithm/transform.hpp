// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_ALGORITHM_TRANSFORM_HPP
#define TETL_ALGORITHM_TRANSFORM_HPP

namespace etl {

/// \ingroup algorithm
/// @{

/// Applies the given function to a range and stores the result in
/// another range, beginning at dest. The unary operation op is applied to
/// the range defined by `[first, last)`.
///
/// https://en.cppreference.com/w/cpp/algorithm/transform
///
/// \param first The first range of elements to transform.
/// \param last The first range of elements to transform.
/// \param dest The beginning of the destination range, may be equal to first.
/// \param op Unary operation function object that will be applied.
///
/// \ingroup algorithm
template <typename InputIt, typename OutputIt, typename UnaryOp>
constexpr auto transform(InputIt first, InputIt last, OutputIt dest, UnaryOp op) -> OutputIt
{
    for (; first != last; ++first, (void)++dest) {
        *dest = op(*first);
    }
    return dest;
}

template <typename InputIt1, typename InputIt2, typename OutputIt, typename BinaryOp>
constexpr auto transform(InputIt1 first1, InputIt1 last1, InputIt2 first2, OutputIt dest, BinaryOp op) -> OutputIt
{
    for (; first1 != last1; ++first1, (void)++first2, ++dest) {
        *dest = op(*first1, *first2);
    }
    return dest;
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_TRANSFORM_HPP
