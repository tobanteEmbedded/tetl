// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_VARIANT_SIZE_HPP
#define TETL_VARIANT_VARIANT_SIZE_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/integral_constant.hpp"
#include "etl/_variant/variant_fwd.hpp"

namespace etl {

template <typename... Ts>
struct variant_size<variant<Ts...>> : integral_constant<etl::size_t, sizeof...(Ts)> { };

template <typename T>
struct variant_size<T const> : variant_size<T>::type { };

template <typename T>
struct variant_size<T volatile> : variant_size<T>::type { };

template <typename T>
struct variant_size<T const volatile> : variant_size<T>::type { };

template <typename T>
inline constexpr auto variant_size_v = variant_size<T>::value;

} // namespace etl

#endif // TETL_VARIANT_VARIANT_SIZE_HPP
