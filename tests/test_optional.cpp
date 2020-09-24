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

#include "etl/optional.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("optional: construct()", "[optional]", bool, etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    CHECK_FALSE(etl::optional<TestType> {}.has_value());
    CHECK_FALSE(etl::optional<TestType> {etl::nullopt}.has_value());
}

TEMPLATE_TEST_CASE("optional: construct(value_type)", "[optional]", bool, etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    CHECK(etl::optional<TestType> {TestType {}}.has_value());
    CHECK(etl::optional<TestType> {TestType {1}}.has_value());
}

TEMPLATE_TEST_CASE("optional: operator=(nullopt)", "[optional]", bool, etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::optional<TestType> opt {};
    CHECK_FALSE(opt.has_value());
    opt = etl::nullopt;
    CHECK_FALSE(opt.has_value());
}

TEMPLATE_TEST_CASE("optional: operator=(value_type)", "[optional]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::optional<TestType> opt {};
    CHECK_FALSE(opt.has_value());
    opt = TestType {42};
    CHECK(opt.has_value());
    CHECK(opt.value() == TestType {42});
}

TEMPLATE_TEST_CASE("optional: operator=(optional)", "[optional]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    SECTION("None have values")
    {
        etl::optional<TestType> opt {};
        CHECK_FALSE(opt.has_value());
        opt = etl::optional<TestType> {};
        CHECK_FALSE(opt.has_value());
    }

    SECTION("First has value")
    {
        etl::optional<TestType> opt {42};
        CHECK(opt.has_value());
        CHECK(opt.value() == TestType {42});
        opt = etl::optional<TestType> {};
        CHECK_FALSE(opt.has_value());
    }

    SECTION("Second has value")
    {
        etl::optional<TestType> opt {};
        CHECK_FALSE(opt.has_value());
        opt = etl::optional<TestType> {42};
        CHECK(opt.has_value());
        CHECK(opt.value() == TestType {42});
    }
}

TEMPLATE_TEST_CASE("optional: is_trivially_destructible_v", "[optional]", bool,
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    SECTION("true")
    {
        etl::optional<TestType> opt {};
        STATIC_REQUIRE(etl::is_trivially_destructible_v<decltype(opt)>);
    }

    SECTION("false")
    {
        struct S
        {
            S() = default;
            ~S() { }

            TestType data {};
        };

        etl::optional<S> opt {};
        STATIC_REQUIRE_FALSE(etl::is_trivially_destructible_v<S>);
    }
}

TEMPLATE_TEST_CASE("optional: has_value", "[optional]", bool, etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::optional<TestType> opt {};
    CHECK_FALSE(opt.has_value());
}

TEMPLATE_TEST_CASE("optional: value_or", "[optional]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::optional<TestType> opt {};
    CHECK(opt.value_or(TestType {42}) == TestType {42});
}

TEMPLATE_TEST_CASE("optional: deduction guide", "[optional]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    SECTION("implicit")
    {
        {
            etl::optional opt {TestType {}};
            STATIC_REQUIRE(etl::is_same_v<typename decltype(opt)::value_type, TestType>);
        }

        {
            TestType data {};
            etl::optional opt {data};
            STATIC_REQUIRE(etl::is_same_v<typename decltype(opt)::value_type, TestType>);
        }

        {
            TestType const data {42};
            etl::optional opt {data};
            STATIC_REQUIRE(etl::is_same_v<typename decltype(opt)::value_type, TestType>);
        }
    }

    SECTION("explicit")
    {
        TestType data[2];
        etl::optional opt {data};  // explicit deduction guide is used in this case
        STATIC_REQUIRE(etl::is_same_v<typename decltype(opt)::value_type, TestType*>);
    }
}
