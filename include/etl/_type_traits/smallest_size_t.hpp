// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_SMALLEST_SIZE_T_HPP
#define TETL_TYPE_TRAITS_SMALLEST_SIZE_T_HPP

#include <etl/_type_traits/conditional.hpp>

namespace etl {
/// Smallest unsigned integer type that can represent values in the range [0, N].
/// \ingroup type_traits
// clang-format off
template<unsigned long long N>
using smallest_size_t =
            conditional_t<(N < static_cast<unsigned char>(-1)),     unsigned char,
            conditional_t<(N < static_cast<unsigned short>(-1)),    unsigned short,
            conditional_t<(N < static_cast<unsigned int>(-1)),      unsigned int,
            conditional_t<(N < static_cast<unsigned long>(-1)),     unsigned long,
                                                                    unsigned long long>
        >
    >
>;
// clang-format on

} // namespace etl

#endif // TETL_TYPE_TRAITS_SMALLEST_SIZE_T_HPP
