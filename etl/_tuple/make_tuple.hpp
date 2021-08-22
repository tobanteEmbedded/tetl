

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

#ifndef TETL_TUPLE_MAKE_TUPLE_HPP
#define TETL_TUPLE_MAKE_TUPLE_HPP

#include "etl/_functional/reference_wrapper.hpp"
#include "etl/_tuple/tuple.hpp"
#include "etl/_type_traits/decay.hpp"
#include "etl/_utility/forward.hpp"

namespace etl {
namespace detail {
template <typename T>
struct unwrap_refwrapper {
    using type = T;
};

template <typename T>
struct unwrap_refwrapper<reference_wrapper<T>> {
    using type = T&;
};

template <typename T>
using unwrap_decay_t = typename unwrap_refwrapper<decay_t<T>>::type;

} // namespace detail

/// \brief Creates a tuple object, deducing the target type from the types of
/// arguments.
template <typename... Types>
[[nodiscard]] constexpr auto make_tuple(Types&&... args)
{
    return tuple<detail::unwrap_decay_t<Types>...>(forward<Types>(args)...);
}
} // namespace etl

#endif // TETL_TUPLE_MAKE_TUPLE_HPP
