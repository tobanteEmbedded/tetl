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

#ifndef ETL_EXPERIMENTAL_TESTING_SOURCE_LINE_INFO_HPP
#define ETL_EXPERIMENTAL_TESTING_SOURCE_LINE_INFO_HPP

#include "etl/cstddef.hpp"

namespace etl::test {

struct source_line_info {
    source_line_info() = delete;

    constexpr source_line_info(char const* f, etl::size_t l) noexcept
        : file { f }, line { l }
    {
    }

    char const* file;
    etl::size_t line;
};

} // namespace etl::test

#define TEST_DETAIL_SOURCE_LINE_INFO                                           \
    etl::test::source_line_info(__FILE__, static_cast<etl::size_t>(__LINE__))

#endif // ETL_EXPERIMENTAL_TESTING_SOURCE_LINE_INFO_HPP
