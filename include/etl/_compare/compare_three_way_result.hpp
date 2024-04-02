// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPARE_COMMON_THREE_WAY_RESULT_HPP
#define TETL_COMPARE_COMMON_THREE_WAY_RESULT_HPP

#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/remove_reference.hpp>

namespace etl {

// recommended by Casey Carter
// see also: https://github.com/microsoft/STL/pull/385#discussion_r357894054
/// \ingroup compare
template <typename T, typename U = T>
using compare_three_way_result_t
    = decltype(etl::declval<etl::remove_reference_t<T> const&>() <=> etl::declval<etl::remove_reference_t<U> const&>());

/// \ingroup compare
template <typename T, typename U = T>
struct compare_three_way_result { };

/// \ingroup compare
template <typename T, typename U>
    requires requires { typename compare_three_way_result_t<T, U>; }
struct compare_three_way_result<T, U> {
    using type = compare_three_way_result_t<T, U>;
};

} // namespace etl

#endif // TETL_COMPARE_COMMON_THREE_WAY_RESULT_HPP
