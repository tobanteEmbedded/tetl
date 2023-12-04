// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPARE_THREE_WAY_COMPAREABLE_HPP
#define TETL_COMPARE_THREE_WAY_COMPAREABLE_HPP

#include "etl/_compare/common_comparison_category.hpp"
#include "etl/_compare/partial_ordering.hpp"
#include "etl/_compare/weak_ordering.hpp"
#include "etl/_concepts/boolean_testable.hpp"
#include "etl/_concepts/same_as.hpp"
#include "etl/_concepts/weakly_equality_comparable_with.hpp"
#include "etl/_type_traits/remove_reference.hpp"

namespace etl {
namespace detail {
template <typename T, typename Cat>
concept compares_as = same_as<common_comparison_category_t<T, Cat>, Cat>;

// clang-format off
template<typename T, typename U>
concept partially_ordered_with = requires(remove_reference_t<T> const& t, remove_reference_t<U> const& u) {
    { t <  u } -> boolean_testable;
    { t >  u } -> boolean_testable;
    { t <= u } -> boolean_testable;
    { t >= u } -> boolean_testable;
    { u <  t } -> boolean_testable;
    { u >  t } -> boolean_testable;
    { u <= t } -> boolean_testable;
    { u >= t } -> boolean_testable;
};
// clang-format on

} // namespace detail

// clang-format off
template<typename T, typename Cat = partial_ordering>
concept three_way_comparable =
    weakly_equality_comparable_with<T, T> &&
    detail::partially_ordered_with<T, T> &&
    requires(remove_reference_t<T> const& a, remove_reference_t<T> const& b) {
        { a <=> b } -> detail::compares_as<Cat>;
    };
// clang-format on
} // namespace etl

#endif // TETL_COMPARE_THREE_WAY_COMPAREABLE_HPP
