// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_VARIANT_VARIADIC_UNION_HPP
#define TETL_VARIANT_VARIADIC_UNION_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/index_constant.hpp>
#include <etl/_type_traits/is_trivially_destructible.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_variant/uninitialized_union.hpp>

namespace etl {

template <typename... Ts>
union variadic_union {
};

template <typename T, typename... Ts>
union TETL_TRIVIAL_ABI variadic_union<T, Ts...> {
    explicit constexpr variadic_union(uninitialized_union /*tag*/) { }

    template <typename... Args>
    explicit constexpr variadic_union(index_constant<0> /*index*/, Args&&... args)
        : head(etl::forward<Args>(args)...)
    {
    }

    template <size_t I, typename... Args>
        requires(I > 0)
    explicit constexpr variadic_union(index_constant<I> /*index*/, Args&&... args)
        : tail(index_v<I - 1>, etl::forward<Args>(args)...)
    {
    }

    constexpr variadic_union(variadic_union const& other)                    = default;
    constexpr auto operator=(variadic_union const& other) -> variadic_union& = default;

    constexpr variadic_union(variadic_union&& other)                    = default;
    constexpr auto operator=(variadic_union&& other) -> variadic_union& = default;

    constexpr ~variadic_union()
        requires(is_trivially_destructible_v<T> and ... and is_trivially_destructible_v<Ts>)
    = default;

    constexpr ~variadic_union() { }

    template <size_t I>
    constexpr auto operator[](index_constant<I> /*index*/) & -> auto&
    {
        if constexpr (I == 0) {
            return head;
        } else {
            return tail[index_v<I - 1>];
        }
    }

    template <size_t I>
    constexpr auto operator[](index_constant<I> /*index*/) const& -> auto const&
    {
        if constexpr (I == 0) {
            return head;
        } else {
            return tail[index_v<I - 1>];
        }
    }

    template <size_t I>
    constexpr auto operator[](index_constant<I> /*index*/) && -> auto&&
    {
        if constexpr (I == 0) {
            return etl::move(head);
        } else {
            return etl::move(tail)[index_v<I - 1>];
        }
    }

    template <size_t I>
    constexpr auto operator[](index_constant<I> /*index*/) const&& -> auto const&&
    {
        if constexpr (I == 0) {
            return etl::move(head);
        } else {
            return etl::move(tail)[index_v<I - 1>];
        }
    }

    TETL_NO_UNIQUE_ADDRESS T head;
    TETL_NO_UNIQUE_ADDRESS variadic_union<Ts...> tail;
};

} // namespace etl

#endif // TETL_VARIANT_VARIADIC_UNION_HPP
