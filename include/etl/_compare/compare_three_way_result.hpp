/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPARE_COMMON_THREE_WAY_RESULT_HPP
#define TETL_COMPARE_COMMON_THREE_WAY_RESULT_HPP

#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/remove_reference.hpp"

#if defined(__cpp_impl_three_way_comparison)

namespace etl {

// recommended by Casey Carter
// see also: https://github.com/microsoft/STL/pull/385#discussion_r357894054
// clang-format off
template<typename T, typename U = T>
using compare_three_way_result_t = decltype(
    declval<remove_reference_t<T> const&>() <=>
    declval<remove_reference_t<U> const&>()
);
// clang-format on

template <typename T, typename U = T>
struct compare_three_way_result { };

template <typename T, typename U>
    requires requires { typename compare_three_way_result_t<T, U>; }
struct compare_three_way_result<T, U> {
    using type = compare_three_way_result_t<T, U>;
};

} // namespace etl

#endif

#endif // TETL_COMPARE_COMMON_THREE_WAY_RESULT_HPP
