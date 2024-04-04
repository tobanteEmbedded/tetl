// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TUPLE_TUPLE_HPP
#define TETL_TUPLE_TUPLE_HPP

#include <etl/_config/all.hpp>

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
    auto get_type(index_constant<I> ic) -> T;

    template <typename... Args>
    constexpr tuple_leaf(Args&&... args) : _value{etl::forward<Args>(args)...}
    {
    }

    [[nodiscard]] constexpr auto get_impl(index_constant<I> /*ic*/) & noexcept -> T& { return _value; }

    [[nodiscard]] constexpr auto get_impl(index_constant<I> /*ic*/) const& noexcept -> T const& { return _value; }

    [[nodiscard]] constexpr auto get_impl(index_constant<I> /*ic*/) && noexcept -> T&& { return TETL_MOVE(_value); }

    [[nodiscard]] constexpr auto get_impl(index_constant<I> /*ic*/) const&& noexcept -> T const&&
    {
        return TETL_MOVE(_value);
    }

    constexpr auto swap_impl(index_constant<I> /*ic*/, T& other) noexcept(is_nothrow_swappable_v<T>) -> void
    {
        using etl::swap;
        swap(_value, other);
    }

private:
    TETL_NO_UNIQUE_ADDRESS T _value; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
};

template <typename... Ts>
struct tuple_impl;

template <size_t... Idx, typename... Ts>
struct tuple_impl<etl::index_sequence<Idx...>, Ts...> : tuple_leaf<Idx, Ts>... {
private:
public:
    explicit(not(is_implicit_default_constructible_v<Ts> && ...)) constexpr tuple_impl()
        requires((is_default_constructible_v<Ts> and ...))
        : tuple_leaf<Idx, Ts>{}...
    {
    }

    // No. 2
    explicit(not(is_convertible_v<Ts const&, Ts> && ...)) constexpr tuple_impl(Ts const&... args)
        requires((is_copy_constructible_v<Ts> && ...) && (sizeof...(Ts) > 0))
        : tuple_leaf<Idx, Ts>(args)...
    {
    }

    // No. 3
    template <typename... Args>
        requires((is_constructible_v<Ts, Args &&> && ...) && (sizeof...(Ts) > 0) && (sizeof...(Ts) == sizeof...(Args)))
    explicit(!(is_convertible_v<Args&&, Ts> && ...)) constexpr tuple_impl(Args&&... args)
        : tuple_leaf<Idx, Ts>{etl::forward<Args>(args)}...
    {
    }

    constexpr tuple_impl(tuple_impl const&)     = default;
    constexpr tuple_impl(tuple_impl&&) noexcept = default;

    using tuple_leaf<Idx, Ts>::get_type...;
    using tuple_leaf<Idx, Ts>::get_impl...;

    constexpr auto swap(tuple_impl& other) noexcept((is_nothrow_swappable_v<Ts> && ...)) -> void
    {
        (tuple_leaf<Idx, Ts>::swap_impl(etl::index_v<Idx>, other.get_impl(etl::index_v<Idx>)), ...);
    }
};

} // namespace detail

template <typename... Ts>
struct tuple {
private:
    template <size_t I, typename T>
    friend struct tuple_element;
    template <size_t N, typename... Us>
    friend constexpr auto get(tuple<Us...>& t) -> auto&; // NOLINT
    template <size_t N, typename... Us>
    friend constexpr auto get(tuple<Us...> const& t) -> auto const&; // NOLINT
    template <size_t N, typename... Us>
    friend constexpr auto get(tuple<Us...>&& t) -> auto&&; // NOLINT
    template <size_t N, typename... Us>
    friend constexpr auto get(tuple<Us...> const&& t) -> auto const&&; // NOLINT
    template <typename T, typename... Us>
    friend constexpr auto get(tuple<Us...>& t) -> auto&; // NOLINT
    template <typename T, typename... Us>
    friend constexpr auto get(tuple<Us...> const& t) -> auto const&; // NOLINT
    template <typename T, typename... Us>
    friend constexpr auto get(tuple<Us...>&& t) -> auto&&; // NOLINT
    template <typename T, typename... Us>
    friend constexpr auto get(tuple<Us...> const&& t) -> auto const&&; // NOLINT

    using impl_t = detail::tuple_impl<etl::index_sequence_for<Ts...>, Ts...>;
    TETL_NO_UNIQUE_ADDRESS impl_t _impl; // NOLINT(modernize-use-default-member-init)

    template <etl::size_t I>
    [[nodiscard]] constexpr auto get_impl(etl::index_constant<I> ic) & noexcept -> auto&
    {
        return _impl.get_impl(ic);
    }

    template <etl::size_t I>
    [[nodiscard]] constexpr auto get_impl(etl::index_constant<I> ic) const& noexcept -> auto const&
    {
        return _impl.get_impl(ic);
    }

    template <etl::size_t I>
    [[nodiscard]] constexpr auto get_impl(etl::index_constant<I> ic) && noexcept -> auto&&
    {
        return TETL_MOVE(_impl).get_impl(ic);
    }

    template <etl::size_t I>
    [[nodiscard]] constexpr auto get_impl(etl::index_constant<I> ic) const&& noexcept -> auto const&&
    {
        return TETL_MOVE(_impl).get_impl(ic);
    }

    template <etl::size_t I>
    auto get_type(etl::index_constant<I> ic) -> decltype(_impl.get_type(ic));

public:
    // No. 1
    explicit(not(is_implicit_default_constructible_v<Ts> && ...)) constexpr tuple()
        requires((is_default_constructible_v<Ts> and ...))
        : _impl()
    {
    }

    explicit(not(is_convertible_v<Ts const&, Ts> && ...)) constexpr tuple(Ts const&... args)
        requires((is_copy_constructible_v<Ts> && ...) && (sizeof...(Ts) > 0))
        : _impl(args...)
    {
    }

    // No. 3
    template <typename... Args>
        requires((is_constructible_v<Ts, Args &&> && ...) && (sizeof...(Ts) > 0) && (sizeof...(Ts) == sizeof...(Args)))
    explicit(!(is_convertible_v<Args&&, Ts> && ...)) constexpr tuple(Args&&... args)
        : _impl{etl::forward<Args>(args)...}
    {
    }

    constexpr tuple(tuple const&)     = default;
    constexpr tuple(tuple&&) noexcept = default;

    constexpr auto swap(tuple& other) noexcept((is_nothrow_swappable_v<Ts> && ...)) -> void { _impl.swap(other._impl); }
};

template <etl::size_t I, typename... Ts>
struct tuple_element<I, tuple<Ts...>> {
    static_assert(I < sizeof...(Ts));
    using type = decltype(declval<tuple<Ts...>>().get_type(etl::index_v<I>));
};

template <typename... Ts>
struct tuple_size<tuple<Ts...>> : integral_constant<size_t, sizeof...(Ts)> { };

template <typename... Ts>
inline constexpr auto is_tuple_like<etl::tuple<Ts...>> = true;

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...>& t) -> auto&
{
    static_assert(I < sizeof...(Ts));
    return t.template get_impl<I>(etl::index_v<I>);
}

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...> const& t) -> auto const&
{
    static_assert(I < sizeof...(Ts));
    return t.template get_impl<I>(etl::index_v<I>);
}

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...>&& t) -> auto&&
{
    static_assert(I < sizeof...(Ts));
    return TETL_MOVE(t).template get_impl<I>(etl::index_v<I>);
}

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...> const&& t) -> auto const&&
{
    static_assert(I < sizeof...(Ts));
    return TETL_MOVE(t).template get_impl<I>(etl::index_v<I>);
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
