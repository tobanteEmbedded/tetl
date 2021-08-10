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

#ifndef TETL_CONTAINER_SMALLEST_SIZE_T_HPP
#define TETL_CONTAINER_SMALLEST_SIZE_T_HPP

#include "etl/_cstdint/uint_t.hpp"
#include "etl/_type_traits/conditional.hpp"

#include "etl/limits.hpp"

namespace etl::detail {
/// \brief Smallest fixed-width unsigned integer type that can represent values
/// in the range [0, N].
// clang-format off
template<size_t N>
using smallest_size_t =
            etl::conditional_t<(N < etl::numeric_limits<::etl::uint8_t>::max()),  ::etl::uint8_t,
            etl::conditional_t<(N < etl::numeric_limits<::etl::uint16_t>::max()), ::etl::uint16_t,
            etl::conditional_t<(N < etl::numeric_limits<::etl::uint32_t>::max()), ::etl::uint32_t,
            etl::conditional_t<(N < etl::numeric_limits<::etl::uint64_t>::max()), ::etl::uint64_t,
                                                                 size_t>>>>;
// clang-format on

} // namespace etl::detail

#endif // TETL_CONTAINER_SMALLEST_SIZE_T_HPP