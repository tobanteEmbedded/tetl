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

#ifndef TETL_CSTDLIB_IOTA_HPP
#define TETL_CSTDLIB_IOTA_HPP

#include "etl/_assert/macro.hpp"
#include "etl/_strings/conversion.hpp"
#include "etl/_warning/ignore_unused.hpp"

namespace etl {

/// \brief Converts an integer value to a null-terminated string using the
/// specified base and stores the result in the array given by str parameter.
///
/// \details If base is 10 and value is negative, the resulting string is
/// preceded with a minus sign (-). With any other base, value is always
/// considered unsigned.
///
/// \todo Only base 10 is currently supported.
constexpr auto itoa(int val, char* const buffer, int base) -> char*
{
    auto res = detail::int_to_ascii<int>(val, buffer, base);
    TETL_ASSERT(res.error == detail::int_to_ascii_error::none);
    ignore_unused(res);
    return buffer;
}

} // namespace etl

#endif // TETL_CSTDLIB_IOTA_HPP