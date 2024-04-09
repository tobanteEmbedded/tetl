// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MATH_LOG2_HPP
#define TETL_MATH_LOG2_HPP

namespace etl::detail {

// Compile time version of log2 that handles 0.
template <typename IntT>
[[nodiscard]] static constexpr auto ilog2(IntT value) -> IntT
{
    return (value == 0 || value == 1) ? 0 : 1 + ilog2(value / 2);
}

} // namespace etl::detail

#endif // TETL_MATH_LOG2_HPP
