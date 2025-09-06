// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_VARIANT_VARIANT_ALTERNATIVE_SELECTOR_HPP
#define TETL_VARIANT_VARIANT_ALTERNATIVE_SELECTOR_HPP

#include <etl/_type_traits/declval.hpp>
#include <etl/_variant/overload.hpp>

namespace etl::detail {

template <typename T>
struct variant_alternative_selector_single {
    auto operator()(T /*t*/) const -> T;
};

template <typename... Ts>
inline constexpr auto variant_alternative_selector = etl::overload{variant_alternative_selector_single<Ts>{}...};

template <typename T, typename... Ts>
using variant_alternative_selector_t = decltype(variant_alternative_selector<Ts...>(etl::declval<T>()));

} // namespace etl::detail

#endif // TETL_VARIANT_VARIANT_ALTERNATIVE_SELECTOR_HPP
