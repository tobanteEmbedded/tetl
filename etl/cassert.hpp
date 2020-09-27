/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_CASSERT_HPP
#define TAETL_CASSERT_HPP

#ifndef NDEBUG
#define ETL_ASSERT(Expression)                                                           \
    assertion_handler(#Expression, Expression, __FILE__, __LINE__, nullptr)
#else
#define ETL_ASSERT(Expression)                                                           \
    do {                                                                                 \
    } while (false)
#endif

/**
 * @todo Maybe create a constexpr version of ETL_ASSERT. Otherwise the assertion_handler
 * makes no real sense, because printing is not supported in constexpr context.
 */
inline constexpr auto
assertion_handler([[maybe_unused]] const char* expr_str, [[maybe_unused]] bool expr,
                  [[maybe_unused]] const char* file, [[maybe_unused]] int line,
                  [[maybe_unused]] const char* msg = nullptr) -> void
{
    // I/O is not available, since this function has to work in a constexpr context.
    // Throwing is legal as long as the throwing code is never executed.
#ifndef NDEBUG
    if (!expr) { throw 1; }
#endif
}

#endif  // TAETL_CASSERT_HPP
