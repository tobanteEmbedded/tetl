/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONTAINER_SMALLEST_SIZE_T_HPP
#define TETL_CONTAINER_SMALLEST_SIZE_T_HPP

#include "etl/_cstdint/uint_t.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/conditional.hpp"

namespace etl::detail {
/// \brief Smallest fixed-width unsigned integer type that can represent values
/// in the range [0, N].
// clang-format off
template<size_t N>
using smallest_size_t =
            etl::conditional_t<(N < etl::numeric_limits<etl::uint8_t>::max()),  etl::uint8_t,
            etl::conditional_t<(N < etl::numeric_limits<etl::uint16_t>::max()), etl::uint16_t,
            etl::conditional_t<(N < etl::numeric_limits<etl::uint32_t>::max()), etl::uint32_t,
            etl::conditional_t<(N < etl::numeric_limits<etl::uint64_t>::max()), etl::uint64_t,
                                                                 size_t>>>>;
// clang-format on

} // namespace etl::detail

#endif // TETL_CONTAINER_SMALLEST_SIZE_T_HPP