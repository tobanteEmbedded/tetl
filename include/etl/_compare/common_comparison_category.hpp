/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPARE_COMMON_COMPARISON_CATEGORY_HPP
#define TETL_COMPARE_COMMON_COMPARISON_CATEGORY_HPP

#include "etl/_compare/partial_ordering.hpp"
#include "etl/_compare/strong_ordering.hpp"
#include "etl/_compare/weak_ordering.hpp"
#include "etl/_type_traits/is_same.hpp"

#if defined(__cpp_impl_three_way_comparison)

namespace etl {

namespace detail {

template <unsigned>
struct common_cmpcat_base {
    using type = void;
};
template <>
struct common_cmpcat_base<0U> {
    using type = strong_ordering;
};
template <>
struct common_cmpcat_base<2U> {
    using type = partial_ordering;
};
template <>
struct common_cmpcat_base<4U> {
    using type = weak_ordering;
};
template <>
struct common_cmpcat_base<6U> {
    using type = partial_ordering;
};

} // namespace detail

template <typename... Ts>
struct common_comparison_category :
    // clang-format off
    detail::common_cmpcat_base<(0U | ... |
        (is_same_v<Ts, strong_ordering>  ? 0U :
         is_same_v<Ts, weak_ordering>    ? 4U :
         is_same_v<Ts, partial_ordering> ? 2U : 1U)
    )>
// clang-format on
{ };

template <typename... Ts>
using common_comparison_category_t = typename common_comparison_category<Ts...>::type;

} // namespace etl

#endif

#endif // TETL_COMPARE_COMMON_COMPARISON_CATEGORY_HPP
