// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_SCOPE_SCOPE_EXIT_HPP
#define TETL_SCOPE_SCOPE_EXIT_HPP

#include <etl/_scope/scope_guard.hpp>

namespace etl {

/// \brief The class template `scope_exit` is a general-purpose scope guard
/// intended to call its exit function when a scope is exited. \details A
/// `scope_exit` may be either active, i.e. calls its exit function on
/// destruction, or inactive, i.e. does nothing on destruction. A `scope_exit`
/// is active after constructed from an exit function. A `scope_exit` can become
/// inactive by calling `release()` on it either manually or automatically (by
/// the move constructor). An inactive `scope_exit` may also be obtained by
/// initializing with another inactive `scope_exit`. Once a `scope_exit` is
/// inactive, it cannot become active again.
template <typename FuncT>
struct scope_exit : detail::scope_guard<FuncT, detail::scope_exit_impl> {
    /// Creates a scope_exit from a function, a function object or another
    /// scope_exit.
    using detail::scope_guard<FuncT, detail::scope_exit_impl>::scope_guard;
};

// Deduction guide
template <typename FuncT>
scope_exit(FuncT) -> scope_exit<decay_t<FuncT>>;

} // namespace etl

#endif // TETL_SCOPE_SCOPE_EXIT_HPP
