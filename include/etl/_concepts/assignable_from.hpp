// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_ASSIGNABLE_FROM_HPP
#define TETL_CONCEPTS_ASSIGNABLE_FROM_HPP

#include "etl/_concepts/common_reference_with.hpp"
#include "etl/_concepts/same_as.hpp"
#include "etl/_type_traits/is_lvalue_reference.hpp"
#include "etl/_type_traits/remove_reference.hpp"
#include "etl/_utility/forward.hpp"

#if defined(__cpp_concepts)
namespace etl {

// clang-format off
template<typename LHS, typename RHS>
concept assignable_from =
  is_lvalue_reference_v<LHS> &&
  common_reference_with<
    remove_reference_t<LHS> const&,
    remove_reference_t<RHS> const&> &&
  requires(LHS lhs, RHS&& rhs) {
    { lhs = forward<RHS>(rhs) } -> same_as<LHS>;
  };
// clang-format on

} // namespace etl
#endif

#endif // TETL_CONCEPTS_ASSIGNABLE_FROM_HPP
