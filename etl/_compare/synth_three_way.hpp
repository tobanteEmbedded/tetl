/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPARE_SYNTH_THREE_WAY_HPP
#define TETL_COMPARE_SYNTH_THREE_WAY_HPP

#include "etl/_compare/weak_ordering.hpp"
#include "etl/_concepts/boolean_testable.hpp"
#include "etl/_type_traits/declval.hpp"

#if defined(__cpp_impl_three_way_comparison)

namespace etl {

// // clang-format off
// inline constexpr auto synth_three_way =
//   []<typename T, typename U>(T const& t, U const& u)
//     requires requires {
//       { t < u } -> boolean_testable;
//       { u < t } -> boolean_testable;
//     }
//   {
//     if constexpr (three_way_comparable_with<T, U>) {
//       return t <=> u;
//     } else {
//       if (t < u) { return weak_ordering::less; }
//       if (u < t) { return weak_ordering::greater; }
//       return weak_ordering::equivalent;
//     }
//   };
// // clang-format on

// template <typename T, typename U = T>
// using synth_three_way_result
//     = decltype(synth_three_way(declval<T&>(), declval<U&>()));

} // namespace etl

#endif

#endif // TETL_COMPARE_SYNTH_THREE_WAY_HPP