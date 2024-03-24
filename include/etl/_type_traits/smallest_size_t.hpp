// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_SMALLEST_SIZE_T_HPP
#define TETL_TYPE_TRAITS_SMALLEST_SIZE_T_HPP

#include <etl/_type_traits/conditional.hpp>

namespace etl {
/// \brief Smallest fixed-width unsigned integer type that can represent values
/// in the range [0, N].
// clang-format off
template<unsigned long long N>
using smallest_size_t =
            etl::conditional_t<(N < static_cast<unsigned char>(-1)),     unsigned char,
            etl::conditional_t<(N < static_cast<unsigned short>(-1)),    unsigned short,
            etl::conditional_t<(N < static_cast<unsigned int>(-1)),      unsigned int,
            etl::conditional_t<(N < static_cast<unsigned long>(-1)),     unsigned long,
                                                                    unsigned long long>>>>;
// clang-format on

} // namespace etl

#endif // TETL_TYPE_TRAITS_SMALLEST_SIZE_T_HPP
