// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_ASSIGNABLE_FROM_HPP
#define TETL_CONCEPTS_ASSIGNABLE_FROM_HPP

#include <etl/_concepts/common_reference_with.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_lvalue_reference.hpp>
#include <etl/_type_traits/remove_reference.hpp>
#include <etl/_utility/forward.hpp>

namespace etl {

// clang-format off

/// \headerfile etl/concepts.hpp
/// \ingroup concepts
template<typename LHS, typename RHS>
concept assignable_from =
        etl::is_lvalue_reference_v<LHS>
    // and etl::common_reference_with<etl::remove_reference_t<LHS> const&, etl::remove_reference_t<RHS> const&>
    and requires(LHS lhs, RHS&& rhs) {
        { lhs = etl::forward<RHS>(rhs) } -> etl::same_as<LHS>;
    };

// clang-format on

} // namespace etl

#endif // TETL_CONCEPTS_ASSIGNABLE_FROM_HPP
