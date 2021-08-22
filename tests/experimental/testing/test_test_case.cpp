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

#include "etl/experimental/testing/testing.hpp"

TEST_CASE("A", "")
{
    CHECK_EQUAL(1, 1);
    CHECK_EQUAL(2, 2);

    SECTION("different assertion macro")
    {
        CHECK_NOT_EQUAL(42, 1);
        CHECK_NOT_EQUAL(42, 2);
    }
}

TEST_CASE("B", "")
{
    CHECK(143 == 143);
    CHECK_FALSE(42 == 41);
}

TEST_CASE("C", "")
{
    REQUIRE(143 == 143);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
}

#if not defined(TETL_MSVC)
namespace {
struct TestStruct {
};
} // namespace

TEMPLATE_TEST_CASE("template test", "", int, long, float, double, TestStruct)
{
    using T = TestType;
    etl::ignore_unused(T {});
}
#endif