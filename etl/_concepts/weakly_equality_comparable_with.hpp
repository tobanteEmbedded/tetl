/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONCEPTS_WEAKLY_EQUALITY_COMPAREABLE_WITH_HPP
#define TETL_CONCEPTS_WEAKLY_EQUALITY_COMPAREABLE_WITH_HPP

#include "etl/_concepts/boolean_testable.hpp"
#include "etl/_concepts/convertible_to.hpp"
#include "etl/_type_traits/remove_reference.hpp"

#if defined(__cpp_concepts)
namespace etl {

// clang-format off
template<typename T, typename U>
concept weakly_equality_comparable_with =
  requires(remove_reference_t<T> const& t, remove_reference_t<U> const& u) {
    { t == u } -> boolean_testable;
    { t != u } -> boolean_testable;
    { u == t } -> boolean_testable;
    { u != t } -> boolean_testable;
  };
// clang-format on

} // namespace etl
#endif

#endif // TETL_CONCEPTS_WEAKLY_EQUALITY_COMPAREABLE_WITH_HPP