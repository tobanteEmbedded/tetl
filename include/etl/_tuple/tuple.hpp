// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TUPLE_TUPLE_HPP
#define TETL_TUPLE_TUPLE_HPP

#include <etl/_config/all.hpp>

#include <etl/_mpl/at.hpp>
#include <etl/_tuple/ignore.hpp>
#include <etl/_tuple/is_tuple_like.hpp>
#include <etl/_tuple/tuple_element.hpp>
#include <etl/_tuple/tuple_size.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/index_constant.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/is_copy_constructible.hpp>
#include <etl/_type_traits/is_default_constructible.hpp>
#include <etl/_type_traits/is_implicit_default_constructible.hpp>
#include <etl/_type_traits/is_move_assignable.hpp>
#include <etl/_type_traits/is_move_constructible.hpp>
#include <etl/_type_traits/is_nothrow_move_assignable.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_type_traits/is_nothrow_swappable.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/index_sequence.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_utility/swap.hpp>

namespace etl {

namespace detail {

template <etl::size_t I, typename T>
struct tuple_leaf {
    template <typename... Args>
    constexpr tuple_leaf(Args&&... args)
        : _value(etl::forward<Args>(args)...)
    {
    }

    [[nodiscard]] constexpr auto operator[](index_constant<I> /*idx*/) & noexcept -> T&
    {
        return _value;
    }

    [[nodiscard]] constexpr auto operator[](index_constant<I> /*idx*/) const& noexcept -> T const&
    {
        return _value;
    }

    [[nodiscard]] constexpr auto operator[](index_constant<I> /*idx*/) && noexcept -> T&&
    {
        return etl::move(_value);
    }

    [[nodiscard]] constexpr auto operator[](index_constant<I> /*idx*/) const&& noexcept -> T const&&
    {
        return etl::move(_value);
    }

    constexpr auto swap(index_constant<I> /*idx*/, T& other) noexcept(is_nothrow_swappable_v<T>) -> void
    {
        using etl::swap;
        swap(_value, other);
    }

private:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    TETL_NO_UNIQUE_ADDRESS T _value;
};

template <typename... Ts>
struct tuple_storage;

template <size_t... Idx, typename... Ts>
struct tuple_storage<etl::index_sequence<Idx...>, Ts...> : tuple_leaf<Idx, Ts>... {
    explicit(not(is_implicit_default_constructible_v<Ts> and ...)) constexpr tuple_storage()
        requires((is_default_constructible_v<Ts> and ...))
        : tuple_leaf<Idx, Ts>{}...
    {
    }

    // No. 2
    explicit(not(is_convertible_v<Ts const&, Ts> and ...)) constexpr tuple_storage(Ts const&... args)
        requires((is_copy_constructible_v<Ts> and ...) && (sizeof...(Ts) > 0))
        : tuple_leaf<Idx, Ts>(args)...
    {
    }

    // No. 3
    template <typename... Us>
        requires((is_constructible_v<Ts, Us &&> and ...) && (sizeof...(Ts) > 0) && (sizeof...(Ts) == sizeof...(Us)))
    explicit(!(is_convertible_v<Us&&, Ts> and ...)) constexpr tuple_storage(Us&&... args)
        : tuple_leaf<Idx, Ts>(etl::forward<Us>(args))...
    {
    }

    constexpr tuple_storage(tuple_storage const&)     = default;
    constexpr tuple_storage(tuple_storage&&) noexcept = default;

    using tuple_leaf<Idx, Ts>::operator[]...;

    constexpr auto swap(tuple_storage& other) noexcept((is_nothrow_swappable_v<Ts> && ...)) -> void
    {
        (tuple_leaf<Idx, Ts>::swap(etl::index_v<Idx>, other[etl::index_v<Idx>]), ...);
    }
};

} // namespace detail

template <typename... Ts>
struct tuple {
    // No. 1
    explicit(not(is_implicit_default_constructible_v<Ts> && ...)) constexpr tuple()
        requires((is_default_constructible_v<Ts> and ...))
        : _storage()
    {
    }

    // No. 2
    explicit(not(is_convertible_v<Ts const&, Ts> && ...)) constexpr tuple(Ts const&... args)
        requires((is_copy_constructible_v<Ts> && ...) and (sizeof...(Ts) > 0))
        : _storage(args...)
    {
    }

    // No. 3
    template <typename... Us>
        requires((is_constructible_v<Ts, Us &&> && ...) and (sizeof...(Ts) > 0) and (sizeof...(Ts) == sizeof...(Us)))
    explicit(!(is_convertible_v<Us&&, Ts> && ...)) constexpr tuple(Us&&... args)
        : _storage(etl::forward<Us>(args)...)
    {
    }

    constexpr tuple(tuple const&)     = default;
    constexpr tuple(tuple&&) noexcept = default;

    template <etl::size_t I>
    [[nodiscard]] constexpr auto operator[](etl::index_constant<I> idx) & noexcept -> auto&
    {
        return _storage[idx];
    }

    template <etl::size_t I>
    [[nodiscard]] constexpr auto operator[](etl::index_constant<I> idx) const& noexcept -> auto const&
    {
        return _storage[idx];
    }

    template <etl::size_t I>
    [[nodiscard]] constexpr auto operator[](etl::index_constant<I> idx) && noexcept -> auto&&
    {
        return etl::move(_storage)[idx];
    }

    template <etl::size_t I>
    [[nodiscard]] constexpr auto operator[](etl::index_constant<I> idx) const&& noexcept -> auto const&&
    {
        return etl::move(_storage)[idx];
    }

    constexpr auto swap(tuple& other) noexcept((is_nothrow_swappable_v<Ts> and ...)) -> void
    {
        _storage.swap(other._storage);
    }

private:
    using storage_type = detail::tuple_storage<etl::index_sequence_for<Ts...>, Ts...>;
    TETL_NO_UNIQUE_ADDRESS storage_type _storage; // NOLINT(modernize-use-default-member-init)
};

template <etl::size_t I, typename... Ts>
struct tuple_element<I, tuple<Ts...>> {
    static_assert(I < sizeof...(Ts));
    using type = mpl::at_t<I, mpl::list<Ts...>>;
};

template <typename... Ts>
struct tuple_size<tuple<Ts...>> : integral_constant<size_t, sizeof...(Ts)> { };

template <typename... Ts>
inline constexpr auto is_tuple_like<etl::tuple<Ts...>> = true;

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...>& t) -> auto&
{
    static_assert(I < sizeof...(Ts));
    return t[etl::index_v<I>];
}

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...> const& t) -> auto const&
{
    static_assert(I < sizeof...(Ts));
    return t[etl::index_v<I>];
}

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...>&& t) -> auto&&
{
    static_assert(I < sizeof...(Ts));
    return etl::move(t)[etl::index_v<I>];
}

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...> const&& t) -> auto const&&
{
    static_assert(I < sizeof...(Ts));
    return etl::move(t)[etl::index_v<I>];
}

template <typename... Ts, typename... Us>
    requires(sizeof...(Ts) == sizeof...(Us))
[[nodiscard]] constexpr auto operator==(tuple<Ts...> const& lhs, tuple<Us...> const& rhs) -> bool
{
    if constexpr (sizeof...(Ts) == 0) {
        return false;
    } else {
        return [&]<etl::size_t... Is>(etl::index_sequence<Is...> /*i*/) {
            using etl::get;
            return ((get<Is>(lhs) == get<Is>(rhs)) and ...);
        }(etl::index_sequence_for<Ts...>{});
    }
}

} // namespace etl

#endif // TETL_TUPLE_TUPLE_HPP
