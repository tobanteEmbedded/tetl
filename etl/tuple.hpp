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

#ifndef TETL_TUPLE_HPP
#define TETL_TUPLE_HPP

#include "etl/version.hpp"

// #include "etl/detail/tuple_size.hpp"

/// \file This header is part of the general utility library.

namespace etl {
/// \todo Implement index_sequence & tuple_size
template <typename First, typename... Rest>
struct tuple : public tuple<Rest...> {
    tuple(First f, Rest... rest) : tuple<Rest...>(rest...), first(f) { }

    First first;
};

template <typename First>
struct tuple<First> {
    tuple(First f) : first(f) { }

    First first;
};

namespace detail {
    template <int Index, typename First, typename... Rest>
    struct get_impl {
        static constexpr auto value(tuple<First, Rest...> const* t)
            -> decltype(get_impl<Index - 1, Rest...>::value(t))
        {
            return get_impl<Index - 1, Rest...>::value(t);
        }
    };

    template <typename First, typename... Rest>
    struct get_impl<0, First, Rest...> {
        static constexpr auto value(tuple<First, Rest...> const* t) -> First
        {
            return t->first;
        }
    };

} // namespace detail

template <int Index, typename First, typename... Rest>
constexpr auto get(tuple<First, Rest...> const& t)
    -> decltype(detail::get_impl<Index, First, Rest...>::value(&t))
{
    return detail::get_impl<Index, First, Rest...>::value(&t);
}

// namespace detail
// {
// struct ignore_t
// {
//     template <typename T>
//     constexpr auto operator=( T const&) const -> const ignore_t&
//     {
//         return *this;
//     }
// };
// }  // namespace detail

//
//  /// \brief An object of unspecified type such that any value can be assigned
//  to it with no
//  /// effect. Intended for use with etl::tie when unpacking a etl::tuple, as a
//  placeholder
//  /// for the arguments that are not used.
//
// inline constexpr detail::ignore_t ignore;

//
//  /// \brief Creates a tuple of lvalue references to its arguments or
//  instances of
//  /// etl::ignore.
//
// template <typename... Types>
// constexpr auto tie(Types&... args) -> etl::tuple<Types&...>
// {
//     return etl::tuple<Types&...>(args...);
// }

} // namespace etl

#endif // TETL_TUPLE_HPP
