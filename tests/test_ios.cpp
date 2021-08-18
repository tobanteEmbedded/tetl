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
#include "etl/ios.hpp"

#include "etl/warning.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("ios: ios_base::openmode", "[ios]")
{
    STATIC_REQUIRE(etl::is_bitmask_type_v<etl::ios_base::openmode>);
}

TEST_CASE("ios: ios_base::fmtflags", "[ios]")
{
    STATIC_REQUIRE(etl::is_bitmask_type_v<etl::ios_base::fmtflags>);
}

TEST_CASE("ios: ios_base::iostate", "[ios]")
{
    STATIC_REQUIRE(etl::is_bitmask_type_v<etl::ios_base::iostate>);
}

TEMPLATE_TEST_CASE("ios: ios_base::basic_stringbuf", "[ios]", char, wchar_t)
{
    using CharT = TestType;

    auto sbuf = etl::basic_stringbuf<CharT, 16> {};
    etl::ignore_unused(sbuf);
    SUCCEED();
}
