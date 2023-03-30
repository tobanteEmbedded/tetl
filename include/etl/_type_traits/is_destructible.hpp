// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_DESTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_DESTRUCTIBLE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/disjunction.hpp"
#include "etl/_type_traits/extent.hpp"
#include "etl/_type_traits/is_function.hpp"
#include "etl/_type_traits/is_reference.hpp"
#include "etl/_type_traits/is_scalar.hpp"
#include "etl/_type_traits/is_unbounded_array.hpp"
#include "etl/_type_traits/is_void.hpp"
#include "etl/_type_traits/remove_all_extents.hpp"
#include "etl/_type_traits/type_identity.hpp"

namespace etl {

namespace detail {

struct try_is_destructible_impl {
    template <typename T, typename = decltype(etl::declval<T&>().~T())>
    static auto test(int) -> etl::true_type;

    template <typename>
    static auto test(...) -> etl::false_type;
};

template <typename T>
struct is_destructible_impl : try_is_destructible_impl {
    using type = decltype(test<T>(0));
};

template <typename T, bool = etl::disjunction<etl::is_void<T>, etl::is_function<T>, etl::is_unbounded_array<T>>::value,
    bool = etl::disjunction<etl::is_reference<T>, etl::is_scalar<T>>::value>
struct is_destructible_safe;

template <typename T>
struct is_destructible_safe<T, false, false> : is_destructible_impl<typename etl::remove_all_extents_t<T>>::type { };

template <typename T>
struct is_destructible_safe<T, true, false> : etl::false_type { };

template <typename T>
struct is_destructible_safe<T, false, true> : etl::true_type { };

} // namespace detail

/// \brief Because the C++ program terminates if a destructor throws an
/// exception during stack unwinding (which usually cannot be predicted), all
/// practical destructors are non-throwing even if they are not declared
/// noexcept. All destructors found in the C++ standard library are
/// non-throwing.
///
/// https://en.cppreference.com/w/cpp/types/is_destructible
template <typename T>
struct is_destructible : detail::is_destructible_safe<T> { };

/// \exclude
template <typename Type>
struct is_destructible<Type[]> : false_type { };

/// \exclude
template <>
struct is_destructible<void> : false_type { };

template <typename T>
inline constexpr auto is_destructible_v = is_destructible<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_DESTRUCTIBLE_HPP
