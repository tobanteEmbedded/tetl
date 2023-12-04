// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_NOTHROW_CONVERTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_NOTHROW_CONVERTIBLE_HPP

#include "etl/_config/all.hpp"

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conjunction.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_void.hpp"

namespace etl {

template <typename From, typename To>
struct is_nothrow_convertible : bool_constant<is_void_v<From> && is_void_v<To>> { };

template <typename From, typename To>
// clang-format off
    requires
    requires {
        static_cast<To(*)()>(nullptr);
        { declval<void(&)(To) noexcept>()(declval<From>()) } noexcept;
    }
struct is_nothrow_convertible<From, To> : true_type {};
// clang-format on

template <typename From, typename To>
inline constexpr bool is_nothrow_convertible_v = is_nothrow_convertible<From, To>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_NOTHROW_CONVERTIBLE_HPP
