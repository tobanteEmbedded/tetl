// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_VISIT_HPP
#define TETL_VARIANT_VISIT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_tuple/tuple.hpp>
#include <etl/_type_traits/add_rvalue_reference.hpp>
#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/conditional.hpp>
#include <etl/_type_traits/decay.hpp>
#include <etl/_type_traits/is_lvalue_reference.hpp>
#include <etl/_type_traits/is_reference.hpp>
#include <etl/_type_traits/is_rvalue_reference.hpp>
#include <etl/_type_traits/remove_reference.hpp>
#include <etl/_type_traits/void_t.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/index_sequence.hpp>
#include <etl/_variant/variant_fwd.hpp>

namespace etl {

namespace detail {

template <typename... Ts>
auto variant_access(etl::variant<Ts...> const* v) -> etl::variant<Ts...>;

template <typename... Ts>
auto variant_access(etl::variant2<Ts...> const* v) -> etl::variant2<Ts...>;

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

template <etl::size_t... I>
[[nodiscard]] consteval auto sum(etl::index_sequence<I...> /*seq*/) -> etl::size_t
{
    return (I + ...);
}

template <etl::size_t I, etl::size_t... Is>
[[nodiscard]] consteval auto prepend(etl::index_sequence<Is...> /*seq*/) -> etl::index_sequence<I, Is...>
{
    return {};
}

[[nodiscard]] consteval auto next_seq(etl::index_sequence<> /*i*/, etl::index_sequence<> /*j*/) -> etl::index_sequence<>
{
    return {};
}

template <etl::size_t I, etl::size_t... Is, etl::size_t J, etl::size_t... Js>
consteval auto next_seq(etl::index_sequence<I, Is...> /*i*/, etl::index_sequence<J, Js...> /*j*/)
{
    if constexpr (I + 1 == J) {
        return prepend<0>(next_seq(etl::index_sequence<Is...>{}, etl::index_sequence<Js...>{}));
    } else {
        return etl::index_sequence<I + 1, Is...>{};
    }
}

template <etl::size_t I, typename T>
constexpr auto get(T&& t) -> decltype(auto)
{
    if constexpr (is_variant_v<T>) {
        return etl::unchecked_get<I>(etl::forward<T>(t));
    } else {
        static_assert(I == 0);
        return etl::forward<T>(t);
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

template <typename T, etl::size_t I>
struct indexed_value {
    static constexpr auto index = etl::index_v<I>;

    constexpr explicit indexed_value(T value)
        : _value(etl::forward<T>(value))
    {
    }

    [[nodiscard]] constexpr auto value() const& -> auto& { return _value; }

    [[nodiscard]] constexpr auto value() && -> auto&& { return etl::forward<T>(_value); }

private:
    T _value;
};

template <etl::size_t... Is, etl::size_t... Ms, typename F, typename... Vs>
constexpr auto visit_with_index(etl::index_sequence<Is...> i, etl::index_sequence<Ms...> m, F&& f, Vs&&... vs)
{
    constexpr auto n = next_seq(i, m);
    if constexpr (sum(n) == 0) {
        return f(indexed_value<decltype(get<Is>(etl::forward<Vs>(vs))), Is>{get<Is>(etl::forward<Vs>(vs))}...);
    } else {
        if (etl::tuple(index(vs)...) == etl::tuple(Is...)) {
            return f(indexed_value<decltype(get<Is>(etl::forward<Vs>(vs))), Is>{get<Is>(etl::forward<Vs>(vs))}...);
        }
        return visit_with_index(n, m, etl::forward<F>(f), etl::forward<Vs>(vs)...);
    }
}

template <etl::size_t... Is, etl::size_t... Ms, typename F, typename... Vs>
constexpr auto visit(etl::index_sequence<Is...> i, etl::index_sequence<Ms...> m, F&& f, Vs&&... vs)
{
    constexpr auto n = next_seq(i, m);
    if constexpr (sum(n) == 0) {
        return f(get<Is>(etl::forward<Vs>(vs))...);
    } else {
        if (etl::tuple(index(vs)...) == etl::tuple(Is...)) {
            return f(get<Is>(etl::forward<Vs>(vs))...);
        }
        return visit(n, m, etl::forward<F>(f), etl::forward<Vs>(vs)...);
    }
}

template <typename>
inline constexpr etl::size_t zero = 0;

} // namespace detail

/// Applies the visitor vis (Callable that can be called with any
/// combination of types from variants) to the variants vars.
///
/// Every type in etl::remove_reference_t<Variants>... may be a
/// (possibly const-qualified) specialization of etl::variant.
///
/// - Access index as `v.index`
/// - Access value as `v.value()`
///
/// \ingroup variant
template <typename F, typename... Vs>
constexpr auto visit_with_index(F&& f, Vs&&... vs)
{
    if constexpr (((etl::detail::variant_size<Vs>() == 1) and ...)) {
        return f(etl::detail::indexed_value<decltype(etl::detail::get<0>(etl::forward<Vs>(vs))), 0>(
            etl::detail::get<0>(etl::forward<Vs>(vs))
        )...);
    } else {
        return etl::detail::visit_with_index(
            etl::index_sequence<etl::detail::zero<Vs>...>{},
            etl::index_sequence<etl::detail::variant_size<Vs>()...>{},
            etl::forward<F>(f),
            etl::forward<Vs>(vs)...
        );
    }
}

/// Applies the visitor vis (Callable that can be called with any
/// combination of types from variants) to the variants vars.
///
/// Every type in etl::remove_reference_t<Variants>... may be a
/// (possibly const-qualified) specialization of etl::variant.
///
/// - Copied from https://github.com/rollbear/visit
/// - https://github.com/rollbear/visit/blob/master/LICENSE.txt
///
/// \ingroup variant
template <typename F, typename... Vs>
constexpr auto visit(F&& f, Vs&&... vs)
{
    return etl::visit_with_index([&](auto... parameter) {
        return etl::forward<F>(f)(etl::move(parameter).value()...);
    }, etl::forward<Vs>(vs)...);
}

} // namespace etl

#endif // TETL_VARIANT_VISIT_HPP
