// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_BIT_UINT_HPP
#define TETL_BIT_BIT_UINT_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/disjunction.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl::detail {

template <typename T>
using bit_uint_impl = etl::bool_constant<etl::disjunction_v<
    etl::is_same<T, unsigned char>,
    etl::is_same<T, unsigned short>,
    etl::is_same<T, unsigned int>,
    etl::is_same<T, unsigned long>,
    etl::is_same<T, unsigned long long>>>;

template <typename T>
inline constexpr auto bit_uint_v = bit_uint_impl<T>::value;

template <typename T>
concept bit_uint = bit_uint_v<T>;

} // namespace etl::detail

#endif // TETL_BIT_BIT_UINT_HPP
