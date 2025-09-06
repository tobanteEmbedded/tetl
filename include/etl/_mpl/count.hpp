// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_MPL_COUNT_HPP
#define TETL_MPL_COUNT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_mpl/list.hpp>
#include <etl/_type_traits/integral_constant.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl::mpl {

template <typename Needle, typename Haystack>
struct count;

template <typename Needle, typename... Ts>
struct count<Needle, list<Ts...>> : etl::integral_constant<etl::size_t, (etl::is_same_v<Needle, Ts> + ... + 0)> { };

template <typename Needle, typename Haystack>
inline constexpr auto count_v = count<Needle, Haystack>::value;

} // namespace etl::mpl

#endif // TETL_MPL_COUNT_HPP
