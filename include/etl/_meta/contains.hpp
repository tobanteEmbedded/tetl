// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_META_CONTAINS_HPP
#define TETL_META_CONTAINS_HPP

#include <etl/_meta/list.hpp>
#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl::meta {

template <typename Needle, typename Haystack>
struct contains;

template <typename Needle, typename... Ts>
struct contains<Needle, list<Ts...>> : etl::bool_constant<(etl::is_same_v<Needle, Ts> or ...)> { };

template <typename Needle, typename Haystack>
inline constexpr auto contains_v = contains<Needle, Haystack>::value;

} // namespace etl::meta

#endif // TETL_META_CONTAINS_HPP
