/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_VARIANT_VISIT_HPP
#define TETL_VARIANT_VISIT_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_tuple/tuple.hpp"
#include "etl/_type_traits/add_rvalue_reference.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conditional.hpp"
#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/is_lvalue_reference.hpp"
#include "etl/_type_traits/is_reference.hpp"
#include "etl/_type_traits/is_rvalue_reference.hpp"
#include "etl/_type_traits/remove_reference.hpp"
#include "etl/_type_traits/void_t.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/index_sequence.hpp"
#include "etl/_variant/variant.hpp"

namespace etl {

namespace detail {

template <typename... Ts>
auto variant_access(etl::variant<Ts...> const* v) -> etl::variant<Ts...>;

template <typename T>
using variant_access_t = decltype(variant_access(static_cast<etl::decay_t<T>*>(nullptr)));

template <template <typename...> typename, typename = void, typename...>
struct is_detected_impl : etl::false_type { };

template <template <typename...> typename D, typename... Ts>
struct is_detected_impl<D, etl::void_t<D<Ts...>>, Ts...> : etl::true_type { };

template <template <typename...> typename D, typename... Ts>
using is_detected = typename is_detected_impl<D, void, Ts...>::type;

template <template <typename...> typename D, typename... Ts>
constexpr bool is_detected_v = is_detected<D, Ts...>::value;

template <typename T>
constexpr bool is_variant_v = is_detected_v<variant_access_t, T>;

template <etl::size_t I, etl::size_t... Is>
[[nodiscard]] constexpr auto prepend(etl::index_sequence<Is...> /*ignore*/) -> etl::index_sequence<I, Is...>
{
    return {};
}

[[nodiscard]] constexpr auto next_seq(etl::index_sequence<> /*ignore*/, etl::index_sequence<> /*ignore*/)
    -> etl::index_sequence<>
{
    return {};
}

template <typename T, typename V>
struct copy_referenceness {
    using type = T;
};

template <typename T, typename V>
struct copy_referenceness<T, V&> {
    using type = T&;
};

template <typename T, typename V>
struct copy_referenceness<T, V&&> {
    using type = etl::remove_reference_t<T>&&;
};

template <typename T, typename V>
using copy_referenceness_t = typename copy_referenceness<T, V>::type;

template <typename T, typename TSource>
using as_if_forwarded = etl::conditional_t<!etl::is_reference<TSource> {},
    etl::add_rvalue_reference_t<etl::remove_reference_t<T>>, copy_referenceness_t<T, TSource>>;

template <typename TLike, typename T>
constexpr auto forward_like(T&& x) noexcept -> decltype(auto)
{
    static_assert(!(etl::is_rvalue_reference<decltype(x)> {} && etl::is_lvalue_reference<TLike> {}));

    return static_cast<as_if_forwarded<T, TLike>>(x);
}

template <etl::size_t I, etl::size_t... Is, etl::size_t J, etl::size_t... Js>
constexpr auto next_seq(etl::index_sequence<I, Is...> /*ignore*/, etl::index_sequence<J, Js...> /*ignore*/)
{
    if constexpr (I + 1 == J) {
        return prepend<0>(next_seq(etl::index_sequence<Is...> {}, etl::index_sequence<Js...> {}));
    } else {
        return etl::index_sequence<I + 1, Is...> {};
    }
}

template <etl::size_t... I>
static constexpr auto sum(etl::index_sequence<I...> /*ignore*/) -> etl::size_t
{
    return (I + ...);
}

template <etl::size_t I, typename T>
constexpr auto get(T&& t) -> decltype(auto)
{
    if constexpr (is_variant_v<T>) {
        return etl::get<I>(etl::forward<T>(t));
    } else {
        static_assert(I == 0);
        return etl::forward<T>(t);
    }
}

template <etl::size_t I, typename T>
constexpr auto get_if(T* t)
{
    if constexpr (is_variant_v<T>) {
        return etl::get_if<I>(t);
    } else {
        static_assert(I == 0);
        return t;
    }
}

template <typename V>
constexpr auto variant_size() -> etl::size_t
{
    if constexpr (is_variant_v<V>) {
        return etl::variant_size_v<variant_access_t<V>>;
    } else {
        return 1;
    }
}

template <typename V>
constexpr auto index(V const& v) -> etl::size_t
{
    if constexpr (is_variant_v<V>) {
        return v.index();
    } else {
        return 0;
    }
}

template <etl::size_t... Is, etl::size_t... Ms, typename F, typename... Vs>
constexpr auto visit(etl::index_sequence<Is...> i, etl::index_sequence<Ms...> m, F&& f, Vs&&... vs)
{
    constexpr auto n = next_seq(i, m);
    if constexpr (sum(n) == 0) {
        return f(get<Is>(etl::forward<Vs>(vs))...);
    } else {
        if (etl::tuple(detail::index(vs)...) == etl::tuple(Is...)) { return f(forward_like<Vs>(*get_if<Is>(&vs))...); }
        return visit(n, m, etl::forward<F>(f), etl::forward<Vs>(vs)...);
    }
}

template <typename>
inline constexpr etl::size_t zero = 0;

} // namespace detail

/// \brief Applies the visitor vis (Callable that can be called with any
/// combination of types from variants) to the variants vars.
///
/// \details Every type in etl::remove_reference_t<Variants>... may be a
/// (possibly const-qualified) specialization of etl::variant. It is unspecified
/// whether other argument types, e.g. a class derived from a etl::variant, are
/// supported.
///
/// Copied from https://github.com/rollbear/visit
/// https://github.com/rollbear/visit/blob/master/LICENSE.txt
template <typename F, typename... Vs>
constexpr auto visit(F&& f, Vs&&... vs)
{
    if constexpr (((detail::variant_size<Vs>() == 1) && ...)) {
        return f(detail::forward_like<Vs>(*detail::get_if<0>(&vs))...);
    } else {
        return detail::visit(etl::index_sequence<detail::zero<Vs>...> {},
            etl::index_sequence<detail::variant_size<Vs>()...> {}, etl::forward<F>(f), etl::forward<Vs>(vs)...);
    }
}

} // namespace etl

#endif // TETL_VARIANT_VISIT_HPP
