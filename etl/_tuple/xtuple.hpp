// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_TUPLE_XTUPLE_HPP
#define TETL_TUPLE_XTUPLE_HPP

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
template <size_t Size>
using make_tuple_indices =
    typename make_integer_sequence<size_t, Size>::to_tuple_indices;
}

template <size_t I, typename T>
struct _tuple_leaf {
    auto _get_type(integral_constant<size_t, I> ic) -> T;

    template <typename... Args>
    constexpr _tuple_leaf(Args&&... args) : value_ { forward<Args>(args)... }
    {
    }

    constexpr auto _get(integral_constant<size_t, I> /*ignore*/) noexcept -> T&
    {
        return value_;
    }

    constexpr auto _get(integral_constant<size_t, I> /*ignore*/) const noexcept
        -> T const&
    {
        return value_;
    }

    constexpr auto _swap(integral_constant<size_t, I> /*ignore*/,
        T& other) noexcept(is_nothrow_swappable_v<T>) -> void
    {
        using etl::swap;
        swap(value_, other);
    }

private:
    T value_;
};

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
} // namespace detail

template <typename... Ts>
struct _tuple_constraints {
    // This overload participates in overload resolution only if
    // is_default_constructible_v<Ts> is true for all i
    template <typename>
    static constexpr auto ctor_1_sfinae
        = (is_default_constructible_v<Ts> && ...);

    // The ctor is explicit if and only if Ts is not
    // copy-list-initializable from {} for at least one i.
    template <typename>
    static constexpr auto ctor_1_explicit
        = !(detail::is_implicit_default_constructible_v<Ts> && ...);

    template <typename>
    using enable_ctor_1_implicit
        = enable_if_t<(ctor_1_sfinae<Ts...> && (!ctor_1_explicit<Ts...>)),
            bool>;

    template <typename>
    using enable_ctor_1_explicit
        = enable_if_t<(ctor_1_sfinae<Ts...> && ctor_1_explicit<Ts...>), bool>;

    // This overload participates in overload resolution only if
    // sizeof...(Ts) >= 1 and is_copy_constructible_v<Ts> is true for all i.
    template <typename>
    static constexpr auto ctor_2_sfinae
        = (is_copy_constructible_v<Ts> && ...) && (sizeof...(Ts) > 0);

    // This ctor is explicit if and only if is_convertible_v<Ts const&, Ts> is
    // false for at least one i.
    template <typename>
    static constexpr auto ctor_2_explicit
        = !(is_convertible_v<Ts const&, Ts> && ...);

    template <typename Tag>
    using enable_ctor_2_implicit
        = enable_if_t<(ctor_2_sfinae<Ts...> && (!ctor_2_explicit<Ts...>)), Tag>;

    template <typename>
    using enable_ctor_2_explicit
        = enable_if_t<(ctor_2_sfinae<Ts...> && ctor_2_explicit<Ts...>), bool>;

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
    using enable_ctor_3_implicit = enable_if_t<
        (ctor_3_sfinae<Ts..., Us...> && (!ctor_3_explicit<Ts..., Us...>)),
        bool>;

    template <typename... Us>
    using enable_ctor_3_explicit = enable_if_t<
        (ctor_3_sfinae<Ts..., Us...> && ctor_3_explicit<Ts..., Us...>), bool>;
};

template <typename... Ts>
struct _tuple_impl;

template <size_t... Idx, typename... Ts>
struct _tuple_impl<detail::tuple_indices<Idx...>, Ts...>
    : _tuple_leaf<Idx, Ts>... {
private:
    using _tuple_leaf<Idx, Ts>::_get...;

public:
    // No. 2
    constexpr _tuple_impl(Ts const&... args) : _tuple_leaf<Idx, Ts> { args }...
    {
    }

    // No. 3
    template <typename... Args>
    constexpr _tuple_impl(Args&&... args)
        : _tuple_leaf<Idx, Ts> { forward<Args>(args) }...
    {
    }

    constexpr _tuple_impl(_tuple_impl const&) = default;
    constexpr _tuple_impl(_tuple_impl&&)      = default;

    using _tuple_leaf<Idx, Ts>::_get_type...;

    template <size_t I>
    constexpr auto& _get(integral_constant<size_t, I> ic)
    {
        return _get(ic);
    }
    template <size_t I>
    constexpr auto const& _get(integral_constant<size_t, I> ic) const
    {
        return _get(ic);
    }

    constexpr auto swap(_tuple_impl& other) noexcept(
        (is_nothrow_swappable_v<Ts> && ...)) -> void
    {
        (_tuple_leaf<Idx, Ts>::_swap(integral_constant<size_t, Idx> {},
             other._get(integral_constant<size_t, Idx> {})),
            ...);
    }
};

template <typename... Ts>
struct tuple_size<_tuple_impl<Ts...>>
    : integral_constant<size_t, sizeof...(Ts) - 1> {
};

template <size_t... Idx, typename... Ts, typename... Us>
constexpr auto _tuple_equal(
    _tuple_impl<detail::tuple_indices<Idx...>, Ts...> const& lhs,
    _tuple_impl<detail::tuple_indices<Idx...>, Us...> const& rhs) -> bool
{
    static_assert(sizeof...(Ts) != 0);
    return ((lhs.template _get<Idx>(integral_constant<size_t, Idx> {})
                == rhs.template _get<Idx>(integral_constant<size_t, Idx> {}))
            && ...);
}

template <typename... Ts>
using xtuple = _tuple_impl<detail::make_tuple_indices<sizeof...(Ts)>, Ts...>;

template <size_t N, typename... Ts>
constexpr auto& get(xtuple<Ts...>& t)
{
    return t.template _get<N>(integral_constant<size_t, N> {});
}

template <size_t N, typename... Ts>
constexpr auto const& get(xtuple<Ts...> const& t)
{
    return t.template _get<N>(integral_constant<size_t, N> {});
}

template <size_t I, typename... Ts>
struct tuple_element<I, xtuple<Ts...>> {
    static_assert(I < sizeof...(Ts));
    using type = decltype(declval<xtuple<Ts...>>()._get_type(
        integral_constant<size_t, I> {}));
};

template <typename... Ts, typename... Us>
constexpr auto operator==(xtuple<Ts...> const& lhs, xtuple<Us...> const& rhs)
    -> bool
{
    static_assert(sizeof...(Ts) == sizeof...(Us));
    if constexpr (sizeof...(Ts) == 0) {
        return false;
    } else {
        return _tuple_equal(lhs, rhs);
    }
}

template <typename... Ts, typename... Us>
constexpr auto operator!=(xtuple<Ts...> const& lhs, xtuple<Us...> const& rhs)
    -> bool
{
    static_assert(sizeof...(Ts) == sizeof...(Us));
    return !(lhs == rhs);
}

} // namespace etl

#endif // TETL_TUPLE_XTUPLE_HPP