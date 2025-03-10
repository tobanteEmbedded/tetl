// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_INDEX_OF_HPP
#define TETL_META_INDEX_OF_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_meta/list.hpp>
#include <etl/_type_traits/integral_constant.hpp>

namespace etl::meta {

template <typename T, typename List>
struct index_of;

template <typename T, typename List>
inline constexpr auto index_of_v = index_of<T, List>::value;

template <typename Head, typename... Tail>
struct index_of<Head, list<Head, Tail...>> : etl::integral_constant<etl::size_t, 0> { };

template <typename T, typename Head, typename... Tail>
struct index_of<T, list<Head, Tail...>> : etl::integral_constant<etl::size_t, index_of_v<T, list<Tail...>> + 1> { };

} // namespace etl::meta

#endif // TETL_META_INDEX_OF_HPP
