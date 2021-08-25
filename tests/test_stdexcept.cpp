/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
