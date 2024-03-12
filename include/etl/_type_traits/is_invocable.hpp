// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_INVOCABLE_HPP
#define TETL_TYPE_TRAITS_IS_INVOCABLE_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/invoke_result.hpp>
#include <etl/_type_traits/is_void.hpp>
#include <etl/_type_traits/void_t.hpp>

namespace etl {

// clang-format off
namespace detail {

template <typename Result, typename Ret, bool = etl::is_void_v<Ret>, typename = void>
struct is_invocable_impl : etl::false_type { };

template <typename Result, typename Ret>
struct is_invocable_impl<Result, Ret, true, etl::void_t<typename Result::type>> : etl::true_type { };

// Check if the return type can be converted to T
template <typename Result, typename Ret>
struct is_invocable_impl<Result, Ret, false, etl::void_t<typename Result::type>> {
    static auto get_t() -> typename Result::type;
    template <typename T> static auto use_t(T /*ignore*/) -> void;
    template <typename T, typename = decltype(use_t<T>(get_t()))> static auto check_converts_to_t(int /*ignore*/) -> etl::true_type;
    template <typename T> static auto check_converts_to_t(...) -> etl::false_type;
    using type = decltype(check_converts_to_t<Ret>(1));
};

} // namespace detail

// clang-format on

template <typename Fn, typename... ArgTypes>
struct is_invocable : detail::is_invocable_impl<invoke_result<Fn, ArgTypes...>, void>::type { };

template <typename Fn, typename... ArgTypes>
inline constexpr auto is_invocable_v = is_invocable<Fn, ArgTypes...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_INVOCABLE_HPP
