// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_NUMERIC_TRANSORM_REDUCE_HPP
#define TETL_NUMERIC_TRANSORM_REDUCE_HPP

namespace etl {

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

#endif // TETL_NUMERIC_TRANSORM_REDUCE_HPP
