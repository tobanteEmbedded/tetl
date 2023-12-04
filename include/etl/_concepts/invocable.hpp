// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_INVOCABLE_HPP
#define TETL_CONCEPTS_INVOCABLE_HPP

#include "etl/_functional/invoke.hpp"
#include "etl/_utility/forward.hpp"

namespace etl {

template <typename F, typename... Args>
concept invocable = requires(F&& f, Args&&... args) { etl::invoke(etl::forward<F>(f), etl::forward<Args>(args)...); };

} // namespace etl

#endif // TETL_CONCEPTS_INVOCABLE_HPP
