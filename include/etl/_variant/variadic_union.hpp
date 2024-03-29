// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_VARIADIC_UNION_HPP
#define TETL_VARIANT_VARIADIC_UNION_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/integral_constant.hpp>
#include <etl/_type_traits/is_trivially_destructible.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

struct uninitialized_union { };

template <typename... Ts>
union variadic_union {
};

template <typename T, typename... Ts>
union variadic_union<T, Ts...> {
    explicit constexpr variadic_union(etl::uninitialized_union /*tag*/) { }

    template <typename... Args>
    explicit constexpr variadic_union(etl::index_constant<0> /*index*/, Args&&... args) : head(TETL_FORWARD(args)...)
    {
    }

    template <etl::size_t I, typename... Args>
        requires(I > 0)
    explicit constexpr variadic_union(etl::index_constant<I> /*index*/, Args&&... args)
        : tail(etl::index_c<I - 1>, TETL_FORWARD(args)...)
    {
    }

    constexpr variadic_union(variadic_union const& other)                    = default;
    constexpr auto operator=(variadic_union const& other) -> variadic_union& = default;

    constexpr variadic_union(variadic_union&& other)                    = default;
    constexpr auto operator=(variadic_union&& other) -> variadic_union& = default;

    constexpr ~variadic_union()
        requires(etl::is_trivially_destructible_v<T> and ... and etl::is_trivially_destructible_v<Ts>)
    = default;

    constexpr ~variadic_union() { }

    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> /*index*/) & -> auto&
    {
        if constexpr (I == 0) {
            return head;
        } else {
            return tail[etl::index_c<I - 1>];
        }
    }

    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> /*index*/) const& -> auto const&
    {
        if constexpr (I == 0) {
            return head;
        } else {
            return tail[etl::index_c<I - 1>];
        }
    }

    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> /*index*/) && -> auto&&
    {
        if constexpr (I == 0) {
            return TETL_MOVE(head);
        } else {
            return TETL_MOVE(tail)[etl::index_c<I - 1>];
        }
    }

    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> /*index*/) const&& -> auto const&&
    {
        if constexpr (I == 0) {
            return TETL_MOVE(head);
        } else {
            return TETL_MOVE(tail)[etl::index_c<I - 1>];
        }
    }

    TETL_NO_UNIQUE_ADDRESS T head;
    TETL_NO_UNIQUE_ADDRESS etl::variadic_union<Ts...> tail;
};

} // namespace etl

#endif // TETL_VARIANT_VARIADIC_UNION_HPP
