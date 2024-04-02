// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_EXECUTION_EXECUTION_POLICY_HPP
#define TETL_EXECUTION_EXECUTION_POLICY_HPP

#include <etl/_execution/is_execution_policy.hpp>

namespace etl {

/// \note Non-standard extension
/// \ingroup execution
template <typename T>
concept execution_policy = etl::is_execution_policy_v<T>;

} // namespace etl

#endif // TETL_EXECUTION_EXECUTION_POLICY_HPP
