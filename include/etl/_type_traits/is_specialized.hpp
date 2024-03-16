

// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_SPECIALIZED_HPP
#define TETL_TYPE_TRAITS_IS_SPECIALIZED_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/void_t.hpp>

namespace etl {

template <template <typename...> typename, typename, typename = void>
struct is_specialized : etl::false_type { };

template <template <typename...> typename Template, typename T>
struct is_specialized<Template, T, etl::void_t<decltype(Template<T>{})>> : etl::true_type { };

template <template <typename...> typename Template, typename T, typename Tag = void>
inline constexpr bool is_specialized_v = etl::is_specialized<Template, T, Tag>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_SPECIALIZED_HPP
