// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch
#ifndef TETL_NUMERIC_TRANSFORM_REDUCE_HPP
#define TETL_NUMERIC_TRANSFORM_REDUCE_HPP

#include <etl/_functional/multiplies.hpp>
#include <etl/_functional/plus.hpp>

namespace etl {

/// https://en.cppreference.com/w/cpp/algorithm/transform_reduce
/// \ingroup numeric
template <typename InputIt1, typename InputIt2, typename T, typename BinaryReductionOp, typename BinaryTransformOp>
[[nodiscard]] constexpr auto transform_reduce(
    InputIt1 first1,
    InputIt1 last1,
    InputIt2 first2,
    T init,
    BinaryReductionOp reduce,
    BinaryTransformOp transform
) -> T
{
    for (; first1 != last1; ++first1, (void)++first2) {
        init = reduce(init, transform(*first1, *first2));
    }
    return init;
}

/// https://en.cppreference.com/w/cpp/algorithm/transform_reduce
/// \ingroup numeric
template <typename InputIt1, typename InputIt2, typename T>
[[nodiscard]] constexpr auto transform_reduce(InputIt1 first1, InputIt1 last1, InputIt2 first2, T init) -> T
{
    return etl::transform_reduce(first1, last1, first2, init, etl::plus(), etl::multiplies());
}

/// https://en.cppreference.com/w/cpp/algorithm/transform_reduce
/// \ingroup numeric
template <typename InputIt, typename T, typename BinaryReductionOp, typename UnaryTransformOp>
[[nodiscard]] constexpr auto
transform_reduce(InputIt first, InputIt last, T init, BinaryReductionOp reduce, UnaryTransformOp transform) -> T
{
    for (; first != last; ++first) {
        init = reduce(init, transform(*first));
    }
    return init;
}

} // namespace etl

#endif // TETL_NUMERIC_TRANSFORM_REDUCE_HPP
