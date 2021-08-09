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

#ifndef TETL_DETAIL_UTILITY_PIECEWISE_CONSTRUCT_HPP
#define TETL_DETAIL_UTILITY_PIECEWISE_CONSTRUCT_HPP

#include "etl/detail/cstddef/size_t.hpp"

namespace etl {

/// \brief etl::piecewise_construct_t is an empty class tag type used to
/// disambiguate between different functions that take two tuple arguments.
///
/// \details The overloads that do not use etl::piecewise_construct_t assume
/// that each tuple argument becomes the element of a pair. The overloads that
/// use etl::piecewise_construct_t assume that each tuple argument is used to
/// construct, piecewise, a new object of specified type, which will become the
/// element of the pair.
///
/// \notes
/// [cppreference.com/w/cpp/utility/piecewise_construct_t](https://en.cppreference.com/w/cpp/utility/piecewise_construct_t)
struct piecewise_construct_t {
    explicit piecewise_construct_t() = default;
};

/// \brief The constant etl::piecewise_construct is an instance of an empty
/// struct tag type etl::piecewise_construct_t.
inline constexpr auto piecewise_construct = piecewise_construct_t {};

} // namespace etl

#endif // TETL_DETAIL_UTILITY_PIECEWISE_CONSTRUCT_HPP