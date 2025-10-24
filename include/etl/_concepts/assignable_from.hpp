// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CONCEPTS_ASSIGNABLE_FROM_HPP
#define TETL_CONCEPTS_ASSIGNABLE_FROM_HPP

#include <etl/_concepts/common_reference_with.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_lvalue_reference.hpp>
#include <etl/_type_traits/remove_reference.hpp>
#include <etl/_utility/forward.hpp>

namespace etl {

/// \headerfile etl/concepts.hpp
/// \ingroup concepts
template <typename LHS, typename RHS>
concept assignable_from = is_lvalue_reference_v<LHS>
                      // and common_reference_with<remove_reference_t<LHS> const&, remove_reference_t<RHS> const&>
                      and requires(LHS lhs, RHS&& rhs) {
                              { lhs = etl::forward<RHS>(rhs) } -> same_as<LHS>;
                          };

} // namespace etl

#endif // TETL_CONCEPTS_ASSIGNABLE_FROM_HPP
