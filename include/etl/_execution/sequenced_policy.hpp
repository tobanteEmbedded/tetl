// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_EXECUTION_SEQUENCED_POLICY_HPP
#define TETL_EXECUTION_SEQUENCED_POLICY_HPP

#include <etl/_execution/is_execution_policy.hpp>

namespace etl::execution {

/// The execution policy type used as a unique type to disambiguate parallel
/// algorithm overloading and require that a parallel algorithm's execution
/// may not be parallelized. The invocations of element access functions in
/// parallel algorithms invoked with this policy (usually specified as
/// etl::execution::seq) are indeterminately sequenced in the calling thread.
///
/// \ingroup execution
struct sequenced_policy { };

/// \relates sequenced_policy
/// \ingroup execution
inline constexpr auto seq = sequenced_policy{};

} // namespace etl::execution

template <>
struct etl::is_execution_policy<etl::execution::sequenced_policy> : etl::true_type { };

#endif // TETL_EXECUTION_SEQUENCED_POLICY_HPP
