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
auto variant_access(variant<Ts...> const* v) -> variant<Ts...>;

template <typename T>
using variant_access_t = decltype(variant_access(static_cast<decay_t<T>*>(nullptr)));

template <template <typename...> typename, typename = void, typename...>
struct is_detected_impl : false_type { };

template <template <typename...> typename D, typename... Ts>
struct is_detected_impl<D, void_t<D<Ts...>>, Ts...> : true_type { };

template <template <typename...> typename D, typename... Ts>
using is_detected = typename is_detected_impl<D, void, Ts...>::type;

template <template <typename...> typename D, typename... Ts>
constexpr bool is_detected_v = is_detected<D, Ts...>::value;

template <typename T>
constexpr bool is_variant_v = is_detected_v<variant_access_t, T>;

template <size_t... I>
[[nodiscard]] consteval auto sum(index_sequence<I...> /*seq*/) -> size_t
{
    return (I + ...);
}

template <size_t I, size_t... Is>
[[nodiscard]] consteval auto prepend(index_sequence<Is...> /*seq*/) -> index_sequence<I, Is...>
{
    return {};
}

[[nodiscard]] consteval auto next_seq(index_sequence<> /*i*/, index_sequence<> /*j*/) -> index_sequence<> { return {}; }

template <size_t I, size_t... Is, size_t J, size_t... Js>
consteval auto next_seq(index_sequence<I, Is...> /*i*/, index_sequence<J, Js...> /*j*/)
{
    if constexpr (I + 1 == J) {
        return prepend<0>(next_seq(index_sequence<Is...>{}, index_sequence<Js...>{}));
    } else {
        return index_sequence<I + 1, Is...>{};
    }
}

template <size_t I, typename T>
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
constexpr auto variant_size() -> size_t
{
    if constexpr (is_variant_v<V>) {
        return variant_size_v<variant_access_t<V>>;
    } else {
        return 1;
    }
}

template <typename V>
constexpr auto index(V const& v) -> size_t
{
    if constexpr (is_variant_v<V>) {
        return v.index();
    } else {
        return 0;
    }
}

template <typename T, size_t I>
struct indexed_value {
    static constexpr auto index = index_v<I>;

    constexpr explicit indexed_value(T value)
        : _value(etl::forward<T>(value))
    {
    }

    [[nodiscard]] constexpr auto value() const& -> auto& { return _value; }

    [[nodiscard]] constexpr auto value() && -> auto&& { return etl::forward<T>(_value); }

private:
    T _value;
};

template <size_t... Is, size_t... Ms, typename F, typename... Vs>
constexpr auto visit_with_index(index_sequence<Is...> i, index_sequence<Ms...> m, F&& f, Vs&&... vs)
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

template <typename>
inline constexpr size_t zero = 0;

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
/// \relates variant
/// \ingroup variant
template <typename F, typename... Vs>
constexpr auto visit_with_index(F&& f, Vs&&... vs)
{
    if constexpr (((detail::variant_size<Vs>() == 1) and ...)) {
        return f(detail::indexed_value<decltype(detail::get<0>(etl::forward<Vs>(vs))), 0>(
            detail::get<0>(etl::forward<Vs>(vs))
        )...);
    } else {
        return detail::visit_with_index(
            index_sequence<detail::zero<Vs>...>{},
            index_sequence<detail::variant_size<Vs>()...>{},
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
/// \relates variant
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
