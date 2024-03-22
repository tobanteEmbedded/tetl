// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_VARIANT_FWD_HPP
#define TETL_VARIANT_VARIANT_FWD_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/add_const.hpp>
#include <etl/_type_traits/add_cv.hpp>
#include <etl/_type_traits/add_pointer.hpp>
#include <etl/_type_traits/add_volatile.hpp>

namespace etl {

template <typename... Types>
struct variant;

template <typename... Types>
struct variant2;

template <typename T>
struct variant_size;

/// \brief Provides compile-time indexed access to the types of the alternatives
/// of the possibly cv-qualified variant, combining cv-qualifications of the
/// variant (if any) with the cv-qualifications of the alternative.
template <size_t I, typename T>
struct variant_alternative;

template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...>& v) -> auto&;

template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...> const& v) -> auto const&;

template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...>&& v) -> auto&&;

template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...> const&& v) -> auto const&&;

template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...>& v) -> auto&;

template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...> const& v) -> auto const&;

template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...>&& v) -> auto&&;

template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...> const&& v) -> auto const&&;

template <typename T, typename... Types>
constexpr auto get_if(variant<Types...>* pv) noexcept -> add_pointer_t<T>; // NOLINT

template <typename T, typename... Types>
constexpr auto get_if(variant<Types...> const* pv) noexcept -> add_pointer_t<T const>; // NOLINT

template <size_t I, typename... Types>
constexpr auto get_if(variant<Types...>* pv) noexcept -> add_pointer_t<typename variant_alternative<
                                                          I,
                                                          variant<Types...>>::type>; // NOLINT

template <size_t I, typename... Types>
constexpr auto get_if(variant<Types...> const* pv) noexcept -> add_pointer_t<typename variant_alternative<
                                                                I,
                                                                variant<Types...>>::type const>; // NOLINT

} // namespace etl

#endif // TETL_VARIANT_VARIANT_FWD_HPP
