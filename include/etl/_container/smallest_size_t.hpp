/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONTAINER_SMALLEST_SIZE_T_HPP
#define TETL_CONTAINER_SMALLEST_SIZE_T_HPP

#include "etl/_type_traits/conditional.hpp"

namespace etl {
/// \brief Smallest fixed-width unsigned integer type that can represent values
/// in the range [0, N].
// clang-format off
template<unsigned long long N>
using smallest_size_t =
            conditional_t<(N < static_cast<unsigned char>(-1)),     unsigned char,
            conditional_t<(N < static_cast<unsigned short>(-1)),    unsigned short,
            conditional_t<(N < static_cast<unsigned int>(-1)),      unsigned int,
            conditional_t<(N < static_cast<unsigned long>(-1)),     unsigned long,
                                                                    unsigned long long>>>>;
// clang-format on

} // namespace etl

#endif // TETL_CONTAINER_SMALLEST_SIZE_T_HPP
