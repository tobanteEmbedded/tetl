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

#ifndef TAETL_CHARCONV_HPP
#define TAETL_CHARCONV_HPP

#include "etl/cstdint.hpp"
#include "etl/system_error.hpp"

namespace etl
{
/// A BitmaskType used to specify floating-point formatting for to_chars and
/// from_chars.
enum class chars_format : etl::uint8_t
{
  scientific = 0x1,
  fixed      = 0x2,
  hex        = 0x4,
  general    = fixed | scientific
};

/// Primitive numerical output conversion.
struct to_chars_result
{
  char* ptr;
  etl::errc ec;

  friend auto operator==(to_chars_result const& lhs,
                         to_chars_result const& rhs) noexcept -> bool
  {
    return lhs.ptr == rhs.ptr && lhs.ec == rhs.ec;
  }
};

/// Primitive numerical input conversion
struct from_chars_result
{
  char* ptr;
  etl::errc ec;

  friend auto operator==(from_chars_result const& lhs,
                         from_chars_result const& rhs) noexcept -> bool
  {
    return lhs.ptr == rhs.ptr && lhs.ec == rhs.ec;
  }
};

}  // namespace etl

#endif  // TAETL_CHARCONV_HPP
