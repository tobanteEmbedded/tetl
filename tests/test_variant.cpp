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
#include "etl/variant.hpp"

#include "catch2/catch.hpp"

TEST_CASE("variant: construct", "[variant]")
{
    auto var = etl::variant<etl::monostate, int> {42};
    // auto const value = var.get<int>();
    // REQUIRE(value == 42);
}

TEST_CASE("variant: holds_alternative", "[variant]")
{
    SECTION("mutable")
    {
        auto var = etl::variant<etl::monostate, int, float, double> {42};
        REQUIRE(etl::holds_alternative<int>(var) == true);
        REQUIRE(etl::holds_alternative<etl::monostate>(var) == false);
        REQUIRE(etl::holds_alternative<float>(var) == false);
        REQUIRE(etl::holds_alternative<double>(var) == false);
    }

    SECTION("const")
    {
        auto const var = etl::variant<etl::monostate, int, float, double> {42.0f};
        REQUIRE(etl::holds_alternative<float>(var) == true);
        REQUIRE(etl::holds_alternative<int>(var) == false);
        REQUIRE(etl::holds_alternative<etl::monostate>(var) == false);
        REQUIRE(etl::holds_alternative<double>(var) == false);
    }
}

TEST_CASE("variant: get_if", "[variant]")
{
    SECTION("mutable")
    {
        auto var = etl::variant<etl::monostate, int, float, double> {42};
        REQUIRE(etl::get_if<int>(&var) != nullptr);
        REQUIRE(*etl::get_if<int>(&var) == 42);

        REQUIRE(etl::get_if<etl::monostate>(&var) == nullptr);
        REQUIRE(etl::get_if<float>(&var) == nullptr);
        REQUIRE(etl::get_if<double>(&var) == nullptr);
    }

    SECTION("const")
    {
        auto const var = etl::variant<etl::monostate, int, float, double> {42};
        REQUIRE(etl::get_if<int>(&var) != nullptr);
        REQUIRE(*etl::get_if<int>(&var) == 42);

        REQUIRE(etl::get_if<etl::monostate>(&var) == nullptr);
        REQUIRE(etl::get_if<float>(&var) == nullptr);
        REQUIRE(etl::get_if<double>(&var) == nullptr);
    }
}