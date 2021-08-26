/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TUPLE_TUPLE_HPP
#define TETL_TUPLE_TUPLE_HPP

#include "etl/_concepts/requires.hpp"
#include "etl/_tuple/ignore.hpp"
#include "etl/_tuple/tuple_element.hpp"
#include "etl/_tuple/tuple_size.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/index_sequence.hpp"
#include "etl/_type_traits/integral_constant.hpp"
#include "etl/_type_traits/is_convertible.hpp"
#include "etl/_type_traits/is_copy_constructible.hpp"
#include "etl/_type_traits/is_default_constructible.hpp"
#include "etl/_type_traits/is_move_assignable.hpp"
#include "etl/_type_traits/is_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_move_assignable.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_swappable.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/move.hpp"
#include "etl/_utility/swap.hpp"

namespace etl {

namespace detail {
template <typename T>
void test_implicit_default_constructible(T);

template <typename T, typename = void,
    typename = typename is_default_constructible<T>::type>
struct is_implicit_default_constructible : false_type {
};

template <typename T>
struct is_implicit_default_constructible<T,
    decltype(test_implicit_default_constructible<T const&>({})), true_type>
    : true_type {
};

template <typename T>
struct is_implicit_default_constructible<T,
    decltype(test_implicit_default_constructible<T const&>({})), false_type>
    : false_type {
};

template <typename T>
inline constexpr auto is_implicit_default_constructible_v
    = is_implicit_default_constructible<T>::value;

template <size_t Size>
using make_tuple_indices =
    typename make_integer_sequence<size_t, Size>::to_tuple_indices;

template <size_t I, typename T>
struct tuple_leaf {
    auto get_type(integral_constant<size_t, I> ic) -> T;

    template <typename... Args>
    constexpr tuple_leaf(Args&&... args) : value_ { forward<Args>(args)... }
    {
    }

    [[nodiscard]] constexpr auto get_impl(
        integral_constant<size_t, I> /*ignore*/) noexcept -> T&
    {
        return value_;
    }

    [[nodiscard]] constexpr auto get_impl(
        integral_constant<size_t, I> /*ignore*/) const noexcept -> T const&
    {
        return value_;
    }

    constexpr auto swap_impl(integral_constant<size_t, I> /*ignore*/,
        T& other) noexcept(is_nothrow_swappable_v<T>) -> void
    {
        using etl::swap;
        swap(value_, other);
    }

private:
    T value_;
};

template <typename... Ts>
struct tuple_constraints {
    // This overload participates in overload resolution only if
    // is_default_constructible_v<Ts> is true for all i
    static constexpr auto ctor_1_sfinae
        = (is_default_constructible_v<Ts> && ...);

    // The ctor is explicit if and only if Ts is not
    // copy-list-initializable from {} for at least one i.
    static constexpr auto ctor_1_explicit
        = !(is_implicit_default_constructible_v<Ts> && ...);

    static constexpr auto enable_ctor_1_implicit
        = ctor_1_sfinae && (!ctor_1_explicit);

    static constexpr auto enable_ctor_1_explicit
        = (ctor_1_sfinae) && (ctor_1_explicit);

    // This overload participates in overload resolution only if
    // sizeof...(Ts) >= 1 and is_copy_constructible_v<Ts> is true for all i.
    static constexpr auto ctor_2_sfinae
        = (is_copy_constructible_v<Ts> && ...) && (sizeof...(Ts) > 0);

    // This ctor is explicit if and only if is_convertible_v<Ts const&, Ts> is
    // false for at least one i.
    static constexpr auto ctor_2_explicit
        = !(is_convertible_v<Ts const&, Ts> && ...);

    static constexpr auto enable_ctor_2_implicit
        = ctor_2_sfinae && (!ctor_2_explicit);

    static constexpr auto enable_ctor_2_explicit
        = ctor_2_sfinae && ctor_2_explicit;

    // This overload participates in overload resolution only if sizeof...(Ts)
    // == sizeof...(Us) and sizeof...(Ts) >= 1 and is_constructible_v<Ts, Us&&>
    // is true for all i.
    template <typename... Us>
    static constexpr auto ctor_3_sfinae         //
        = (is_constructible_v<Ts, Us&&> && ...) //
          && (sizeof...(Ts) > 0)                //
          && (sizeof...(Ts) == sizeof...(Us))   //
        ;

    // The constructor is explicit if and only if is_convertible_v<Us&&, Ts> is
    // false for at least one type.
    template <typename... Us>
    static constexpr auto ctor_3_explicit
        = !(is_convertible_v<Us&&, Ts> && ...);

    template <typename... Us>
    static constexpr auto enable_ctor_3_implicit
        = (ctor_3_sfinae<Us...> && (!ctor_3_explicit<Us...>));

    template <typename... Us>
    static constexpr auto enable_ctor_3_explicit
        = (ctor_3_sfinae<Us...> && ctor_3_explicit<Us...>);
};

template <typename... Ts>
struct tuple_impl;

template <size_t... Idx, typename... Ts>
struct tuple_impl<tuple_indices<Idx...>, Ts...> : tuple_leaf<Idx, Ts>... {
private:
public:
    // No. 1
    TETL_REQUIRES(tuple_constraints<Ts...>::enable_ctor_1_implicit)
    constexpr tuple_impl() : tuple_leaf<Idx, Ts> {}... { }

    TETL_REQUIRES(tuple_constraints<Ts...>::enable_ctor_1_explicit)
    explicit constexpr tuple_impl() : tuple_leaf<Idx, Ts> {}... { }

    // No. 2
    TETL_REQUIRES(tuple_constraints<Ts...>::enable_ctor_2_implicit)
    constexpr tuple_impl(Ts const&... args) : tuple_leaf<Idx, Ts>(args)... { }

    TETL_REQUIRES(tuple_constraints<Ts...>::enable_ctor_2_explicit)
    explicit constexpr tuple_impl(Ts const&... args)
        : tuple_leaf<Idx, Ts> { args }...
    {
    }

    // No. 3
    template <typename... Args>
    constexpr tuple_impl(Args&&... args)
        : tuple_leaf<Idx, Ts> { forward<Args>(args) }...
    {
    }

    constexpr tuple_impl(tuple_impl const&)     = default;
    constexpr tuple_impl(tuple_impl&&) noexcept = default;

    using tuple_leaf<Idx, Ts>::get_type...;
    using tuple_leaf<Idx, Ts>::get_impl...;

    constexpr auto swap(tuple_impl& other) noexcept(
        (is_nothrow_swappable_v<Ts> && ...)) -> void
    {
        (tuple_leaf<Idx, Ts>::swap_impl(integral_constant<size_t, Idx> {},
             other.get_impl(integral_constant<size_t, Idx> {})),
            ...);
    }
};

} // namespace detail

template <typename... Ts>
struct tuple {
private:
    // clang-format off
    template <size_t I, typename T>
    friend struct tuple_element;
    template <size_t N, typename... Us>
    friend constexpr auto get(tuple<Us...>& t) -> auto&; // NOLINT
    template <size_t N, typename... Us>
    friend constexpr auto get(tuple<Us...> const& t) -> auto const&; // NOLINT

    using impl_t = detail::tuple_impl<detail::make_tuple_indices<sizeof...(Ts)>, Ts...>;
    impl_t impl_; // NOLINT(modernize-use-default-member-init)

    template <size_t I>
    [[nodiscard]] constexpr auto get_impl(integral_constant<size_t, I> ic) noexcept -> auto&
    {
        return impl_.get_impl(ic);
    }

    template <size_t I>
    [[nodiscard]] constexpr auto get_impl(integral_constant<size_t, I> ic) const noexcept -> auto const&
    {
        return impl_.get_impl(ic);
    }

    template <size_t I>
    auto get_type(integral_constant<size_t, I> ic) -> decltype(impl_.get_type(ic));
    // clang-format on

public:
    // No. 1
    TETL_REQUIRES(detail::tuple_constraints<Ts...>::enable_ctor_1_implicit)
    constexpr tuple() : impl_() { }

    TETL_REQUIRES(detail::tuple_constraints<Ts...>::enable_ctor_1_explicit)
    explicit constexpr tuple() : impl_ {} { }

    // No. 2
    TETL_REQUIRES(detail::tuple_constraints<Ts...>::enable_ctor_2_implicit)
    constexpr tuple(Ts const&... args) : impl_(args...) { }

    TETL_REQUIRES(detail::tuple_constraints<Ts...>::enable_ctor_2_explicit)
    explicit constexpr tuple(Ts const&... args) : impl_ { args... } { }

    //// No. 3
    // template <typename... Args>
    // constexpr tuple(Args&&... args) : impl_ { forward<Args>(args)... }
    //{
    //}

    constexpr tuple(tuple const&)     = default;
    constexpr tuple(tuple&&) noexcept = default;

    constexpr auto swap(tuple& other) noexcept(
        (is_nothrow_swappable_v<Ts> && ...)) -> void
    {
        impl_.swap(other.impl_);
    }
};

template <typename... Ts>
struct tuple_size<tuple<Ts...>> : integral_constant<size_t, sizeof...(Ts)> {
};

template <size_t N, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...>& t) -> auto&
{
    static_assert(N < sizeof...(Ts));
    return t.template get_impl<N>(integral_constant<size_t, N> {});
}

template <size_t N, typename... Ts>
[[nodiscard]] constexpr auto get(tuple<Ts...> const& t) -> auto const&
{
    static_assert(N < sizeof...(Ts));
    return t.template get_impl<N>(integral_constant<size_t, N> {});
}

template <size_t I, typename... Ts>
struct tuple_element<I, tuple<Ts...>> {
    static_assert(I < sizeof...(Ts));
    using type = decltype(declval<tuple<Ts...>>().get_type(
        integral_constant<size_t, I> {}));
};

namespace detail {

template <size_t... Idx, typename... Ts, typename... Us>
constexpr auto tuple_equal_impl(index_sequence<Idx...> /*i*/,
    tuple<Ts...> const& l, tuple<Us...> const& r) -> bool
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
constexpr auto operator==(tuple<Ts...> const& lhs, tuple<Us...> const& rhs)
    -> bool
{
    static_assert(sizeof...(Ts) == sizeof...(Us));
    if constexpr (sizeof...(Ts) == 0) {
        return false;
    } else {
        return detail::tuple_equal(lhs, rhs);
    }
}

template <typename... Ts, typename... Us>
constexpr auto operator!=(tuple<Ts...> const& lhs, tuple<Us...> const& rhs)
    -> bool
{
    static_assert(sizeof...(Ts) == sizeof...(Us));
    return !(lhs == rhs);
}

} // namespace etl

#endif // TETL_TUPLE_TUPLE_HPP