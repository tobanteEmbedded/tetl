/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_TRANSFORM_HPP
#define TETL_ALGORITHM_TRANSFORM_HPP

namespace etl {

/// \brief Applies the given function to a range and stores the result in
/// another range, beginning at dest. The unary operation op is applied to
/// the range defined by `[first, last)`.
///
/// \param first The first range of elements to transform.
/// \param last The first range of elements to transform.
/// \param dest The beginning of the destination range, may be equal to first.
/// \param op Unary operation function object that will be applied.
///
/// https://en.cppreference.com/w/cpp/algorithm/transform
///
/// \group transform
/// \module Algorithm
template <typename InputIt, typename OutputIt, typename UnaryOp>
constexpr auto transform(InputIt first, InputIt last, OutputIt dest, UnaryOp op) -> OutputIt
{
    for (; first != last; ++first, (void)++dest) { *dest = op(*first); }
    return dest;
}

/// \group transform
template <typename InputIt1, typename InputIt2, typename OutputIt, typename BinaryOp>
constexpr auto transform(InputIt1 first1, InputIt1 last1, InputIt2 first2, OutputIt dest, BinaryOp op) -> OutputIt
{
    for (; first1 != last1; ++first1, (void)++first2, ++dest) { *dest = op(*first1, *first2); }
    return dest;
}

} // namespace etl

#endif // TETL_ALGORITHM_TRANSFORM_HPP