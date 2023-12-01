// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TUPLE_TUPLE_HPP
#define TETL_TUPLE_TUPLE_HPP

#include <etl/_tuple/ignore.hpp>
#include <etl/_tuple/tuple_element.hpp>
#include <etl/_tuple/tuple_size.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/integral_constant.hpp>
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
#include <etl/_type_traits/type_pack_element.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/index_sequence.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_utility/swap.hpp>

namespace etl {

namespace detail {
template <size_t Size>
using make_tuple_indices = typename make_integer_sequence<size_t, Size>::to_tuple_indices;

template <etl::size_t I, typename T>
struct tuple_leaf {
    auto get_type(integral_constant<size_t, I> ic) -> T;

    template <typename... Args>
    constexpr tuple_leaf(Args&&... args) : _value {forward<Args>(args)...}
    {
    }

    [[nodiscard]] constexpr auto get_impl(integral_constant<size_t, I> /*ignore*/) & noexcept -> T& { return _value; }

    [[nodiscard]] constexpr auto get_impl(integral_constant<size_t, I> /*ignore*/) const& noexcept -> T const&
    {
        return _value;
    }

    [[nodiscard]] constexpr auto get_impl(integral_constant<size_t, I> /*ignore*/) && noexcept -> T&&
    {
        return etl::move(_value);
    }

    [[nodiscard]] constexpr auto get_impl(integral_constant<size_t, I> /*ignore*/) const&& noexcept -> T const&&
    {
        return etl::move(_value);
    }

    constexpr auto swap_impl(integral_constant<size_t, I> /*ignore*/, T& other) noexcept(is_nothrow_swappable_v<T>)
        -> void
    {
        using etl::swap;
        swap(_value, other);
    }

private:
    T _value;
};

template <typename... Ts>
struct tuple_impl;

template <size_t... Idx, typename... Ts>
struct tuple_impl<tuple_indices<Idx...>, Ts...> : tuple_leaf<Idx, Ts>... {
private:
public:
    explicit(not(is_implicit_default_constructible_v<Ts> && ...)) constexpr tuple_impl()
        requires((is_default_constructible_v<Ts> and ...))
        : tuple_leaf<Idx, Ts> {}...
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
        requires((is_constructible_v<Ts, Args&&> && ...) && (sizeof...(Ts) > 0) && (sizeof...(Ts) == sizeof...(Args)))
    explicit(!(is_convertible_v<Args&&, Ts> && ...)) constexpr tuple_impl(Args&&... args)
        : tuple_leaf<Idx, Ts> {forward<Args>(args)}...
    {
    }

    constexpr tuple_impl(tuple_impl const&)     = default;
    constexpr tuple_impl(tuple_impl&&) noexcept = default;

    using tuple_leaf<Idx, Ts>::get_type...;
    using tuple_leaf<Idx, Ts>::get_impl...;

    constexpr auto swap(tuple_impl& other) noexcept((is_nothrow_swappable_v<Ts> && ...)) -> void
    {
        (tuple_leaf<Idx, Ts>::swap_impl(
             integral_constant<size_t, Idx> {}, other.get_impl(integral_constant<size_t, Idx> {})),
            ...);
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

    // clang-format off

    using impl_t = detail::tuple_impl<detail::make_tuple_indices<sizeof...(Ts)>, Ts...>;
    impl_t _impl; // NOLINT(modernize-use-default-member-init)

    template <size_t I>
    [[nodiscard]] constexpr auto get_impl(integral_constant<size_t, I> ic) &  noexcept -> auto&
    {
        return _impl.get_impl(ic);
    }

    template <size_t I>
    [[nodiscard]] constexpr auto get_impl(integral_constant<size_t, I> ic) const&  noexcept -> auto const&
    {
        return _impl.get_impl(ic);
    }

    template <size_t I>
    [[nodiscard]] constexpr auto get_impl(integral_constant<size_t, I> ic) && noexcept -> auto&&
    {
        return move(_impl).get_impl(ic);
    }

    template <size_t I>
    [[nodiscard]] constexpr auto get_impl(integral_constant<size_t, I> ic) const&&  noexcept -> auto const&&
    {
        return move(_impl).get_impl(ic);
    }

    template <size_t I>
    auto get_type(integral_constant<size_t, I> ic) -> decltype(_impl.get_type(ic));
    // clang-format on

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
        requires((is_constructible_v<Ts, Args&&> && ...) && (sizeof...(Ts) > 0) && (sizeof...(Ts) == sizeof...(Args)))
    explicit(!(is_convertible_v<Args&&, Ts> && ...)) constexpr tuple(Args&&... args) : _impl {forward<Args>(args)...}
    {
    }

    constexpr tuple(tuple const&)     = default;
    constexpr tuple(tuple&&) noexcept = default;

    constexpr auto swap(tuple& other) noexcept((is_nothrow_swappable_v<Ts> && ...)) -> void { _impl.swap(other._impl); }
};

template <typename... Ts>
struct tuple_size<tuple<Ts...>> : integral_constant<size_t, sizeof...(Ts)> { };

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...>& t) -> auto&
{
    static_assert(I < sizeof...(Ts));
    return t.template get_impl<I>(integral_constant<size_t, I> {});
}

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...> const& t) -> auto const&
{
    static_assert(I < sizeof...(Ts));
    return t.template get_impl<I>(integral_constant<size_t, I> {});
}

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...>&& t) -> auto&&
{
    static_assert(I < sizeof...(Ts));
    return etl::move(t).template get_impl<I>(integral_constant<size_t, I> {});
}

template <etl::size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...> const&& t) -> auto const&&
{
    static_assert(I < sizeof...(Ts));
    return etl::move(t).template get_impl<I>(integral_constant<size_t, I> {});
}

template <etl::size_t I, typename... Ts>
struct tuple_element<I, tuple<Ts...>> {
    static_assert(I < sizeof...(Ts));
    using type = decltype(declval<tuple<Ts...>>().get_type(integral_constant<size_t, I> {}));
};

namespace detail {

template <size_t... Idx, typename... Ts, typename... Us>
constexpr auto tuple_equal_impl(index_sequence<Idx...> /*i*/, tuple<Ts...> const& l, tuple<Us...> const& r) -> bool
{
    return ((get<Idx>(l) == get<Idx>(r)) && ...);
}

template <typename... Ts, typename... Us>
constexpr auto tuple_equal(tuple<Ts...> const& l, tuple<Us...> const& r) -> bool
{
    static_assert(sizeof...(Ts) != 0);
    static_assert(sizeof...(Ts) == sizeof...(Us));
    return tuple_equal_impl(make_index_sequence<sizeof...(Ts)> {}, l, r);
}
} // namespace detail

template <typename... Ts, typename... Us>
constexpr auto operator==(tuple<Ts...> const& lhs, tuple<Us...> const& rhs) -> bool
{
    static_assert(sizeof...(Ts) == sizeof...(Us));
    if constexpr (sizeof...(Ts) == 0) {
        return false;
    } else {
        return detail::tuple_equal(lhs, rhs);
    }
}

template <typename... Ts, typename... Us>
constexpr auto operator!=(tuple<Ts...> const& lhs, tuple<Us...> const& rhs) -> bool
{
    static_assert(sizeof...(Ts) == sizeof...(Us));
    return !(lhs == rhs);
}

} // namespace etl

#endif // TETL_TUPLE_TUPLE_HPP
