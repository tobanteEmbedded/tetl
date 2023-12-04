// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_PREDICATE_HPP
#define TETL_CONCEPTS_PREDICATE_HPP

#include "etl/_concepts/boolean_testable.hpp"
#include "etl/_concepts/regular_invocable.hpp"
#include "etl/_type_traits/invoke_result.hpp"

namespace etl {

template <typename F, typename... Args>
concept predicate = regular_invocable<F, Args...> and boolean_testable<invoke_result_t<F, Args...>>;

} // namespace etl

#endif // TETL_CONCEPTS_PREDICATE_HPP
