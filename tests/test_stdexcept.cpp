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

#include "etl/exception.hpp"
#include "etl/stdexcept.hpp"

#include "etl/type_traits.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("stdexcept: logic_error", "[stdexcept]")
{
    STATIC_REQUIRE(etl::is_default_constructible_v<etl::logic_error>);
    STATIC_REQUIRE(etl::is_constructible_v<etl::logic_error, char const*>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::exception, etl::logic_error>);
}

TEST_CASE("stdexcept: domain_error", "[stdexcept]")
{
    STATIC_REQUIRE(etl::is_default_constructible_v<etl::domain_error>);
    STATIC_REQUIRE(etl::is_constructible_v<etl::domain_error, char const*>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::logic_error, etl::domain_error>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::exception, etl::domain_error>);
}

TEST_CASE("stdexcept: invalid_argument", "[stdexcept]")
{
    STATIC_REQUIRE(etl::is_default_constructible_v<etl::invalid_argument>);
    STATIC_REQUIRE(etl::is_constructible_v<etl::invalid_argument, char const*>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::logic_error, etl::invalid_argument>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::exception, etl::invalid_argument>);
}

TEST_CASE("stdexcept: length_error", "[stdexcept]")
{
    STATIC_REQUIRE(etl::is_default_constructible_v<etl::length_error>);
    STATIC_REQUIRE(etl::is_constructible_v<etl::length_error, char const*>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::logic_error, etl::length_error>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::exception, etl::length_error>);
}

TEST_CASE("stdexcept: out_of_range", "[stdexcept]")
{
    STATIC_REQUIRE(etl::is_default_constructible_v<etl::out_of_range>);
    STATIC_REQUIRE(etl::is_constructible_v<etl::out_of_range, char const*>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::logic_error, etl::out_of_range>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::exception, etl::out_of_range>);
}

TEST_CASE("stdexcept: runtime_error", "[stdexcept]")
{
    STATIC_REQUIRE(etl::is_default_constructible_v<etl::runtime_error>);
    STATIC_REQUIRE(etl::is_constructible_v<etl::runtime_error, char const*>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::exception, etl::runtime_error>);
}

TEST_CASE("stdexcept: range_error", "[stdexcept]")
{
    STATIC_REQUIRE(etl::is_default_constructible_v<etl::range_error>);
    STATIC_REQUIRE(etl::is_constructible_v<etl::range_error, char const*>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::runtime_error, etl::range_error>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::exception, etl::range_error>);
}

TEST_CASE("stdexcept: overflow_error", "[stdexcept]")
{
    STATIC_REQUIRE(etl::is_default_constructible_v<etl::overflow_error>);
    STATIC_REQUIRE(etl::is_constructible_v<etl::overflow_error, char const*>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::runtime_error, etl::overflow_error>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::exception, etl::overflow_error>);
}

TEST_CASE("stdexcept: underflow_error", "[stdexcept]")
{
    STATIC_REQUIRE(etl::is_default_constructible_v<etl::underflow_error>);
    STATIC_REQUIRE(etl::is_constructible_v<etl::underflow_error, char const*>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::runtime_error, etl::underflow_error>);
    STATIC_REQUIRE(etl::is_base_of_v<etl::exception, etl::underflow_error>);
}