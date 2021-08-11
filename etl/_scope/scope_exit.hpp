// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.
#ifndef TETL_SCOPE_SCOPE_EXIT_HPP
#define TETL_SCOPE_SCOPE_EXIT_HPP

#include "etl/_scope/scope_guard.hpp"

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