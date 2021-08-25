/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_BIT_UNSIGNED_INT_HPP
#define TETL_BIT_BIT_UNSIGNED_INT_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/disjunction.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl::detail {

template <typename T>
using bit_unsigned_int
    = etl::bool_constant<etl::disjunction_v<etl::is_same<T, unsigned char>,
        etl::is_same<T, unsigned short>, etl::is_same<T, unsigned int>,
        etl::is_same<T, unsigned long>, etl::is_same<T, unsigned long long>>>;

template <typename T>
inline constexpr auto bit_unsigned_int_v = bit_unsigned_int<T>::value;

} // namespace etl::detail

#endif // TETL_BIT_BIT_UNSIGNED_INT_HPP