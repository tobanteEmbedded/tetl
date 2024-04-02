// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_EXECUTION_IS_EXECUTION_POLICY_HPP
#define TETL_EXECUTION_IS_EXECUTION_POLICY_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// Checks whether T is a standard or implementation-defined execution policy type.
/// \ingroup execution
template <typename T>
struct is_execution_policy : etl::false_type { };

/// \relates is_execution_policy
/// \ingroup execution
template <typename T>
inline constexpr bool is_execution_policy_v = is_execution_policy<T>::value;

} // namespace etl

#endif // TETL_EXECUTION_IS_EXECUTION_POLICY_HPP
