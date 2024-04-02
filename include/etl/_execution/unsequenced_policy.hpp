// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_EXECUTION_UNSEQUENCED_POLICY_HPP
#define TETL_EXECUTION_UNSEQUENCED_POLICY_HPP

#include <etl/_execution/is_execution_policy.hpp>

namespace etl::execution {

/// The execution policy type used as a unique type to disambiguate parallel
/// algorithm overloading and indicate that a parallel algorithm's execution
/// may be vectorized, e.g., executed on a single thread using instructions
/// that operate on multiple data items.
///
/// \ingroup execution
struct unsequenced_policy { };

/// \relates unsequenced_policy
/// \ingroup execution
inline constexpr auto unseq = unsequenced_policy{};

} // namespace etl::execution

template <>
struct etl::is_execution_policy<etl::execution::unsequenced_policy> : etl::true_type { };

#endif // TETL_EXECUTION_UNSEQUENCED_POLICY_HPP
