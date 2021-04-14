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

// If you disabled the next line, the default expetion handler will be called at
// runtime which will exit the program with code 1. If an assertion is triggered
// in a constexpr context, you will get a compiler error.
//
// If you enabled the custom handler in your projects, please define the macro
// below in your build system and not in your source code to avoid mixing
// configurations.
#define TETL_CUSTOM_EXCEPTION_HANDLER 1

#include "etl/cassert.hpp"  // for TETL_ASSERT

#include <stdio.h>  // for printf

namespace etl
{
// This function only needs to be implemented if you defined the custom
// exception handler macro.
auto tetl_exception_handler(etl::assert_msg const& msg) -> void
{
  ::printf("EXCEPTION: %s:%d\n", msg.file, msg.line);
}

}  // namespace etl

auto main() -> int
{
  TETL_ASSERT(2 == 2);  // success, nothing is printed
  TETL_ASSERT(2 == 3);  // failure, the exception handler is invoked
  return EXIT_SUCCESS;
}