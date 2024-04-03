// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_COPY_BACKWARD_HPP
#define TETL_ALGORITHM_COPY_BACKWARD_HPP

namespace etl {

/// Copies the elements from the range, defined by `[first, last)`, to
/// another range ending at `dLast`. The elements are copied in reverse order
/// (the last element is copied first), but their relative order is preserved.
///
/// The behavior is undefined if `dLast` is within `(first, last]`.
/// copy must be used instead of copy_backward in that case.
///
/// \returns Iterator to the last element copied.
/// \ingroup algorithm
template <typename BidirIt1, typename BidirIt2>
constexpr auto copy_backward(BidirIt1 first, BidirIt1 last, BidirIt2 dLast) -> BidirIt2
{
    while (first != last) {
        *(--dLast) = *(--last);
    }
    return dLast;
}

} // namespace etl

#endif // TETL_ALGORITHM_COPY_BACKWARD_HPP
