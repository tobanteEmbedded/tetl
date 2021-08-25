/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cstring.hpp"

#include "etl/array.hpp"
#include "etl/string.hpp"
#include "etl/string_view.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("cstring: strcpy", "[cstring]")
{
    char source[32] = { "test" };
    char dest[32] {};

    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
    etl::strcpy(dest, source);

    CHECK(etl::strlen(dest) == 4);
}

TEST_CASE("cstring: strncpy", "[cstring]")
{
    char source[32] = { "test" };
    char dest[32] {};
    etl::strncpy(dest, source, 2);
    CHECK(dest[0] == 't');
    CHECK(dest[1] == 'e');
}

TEST_CASE("cstring: strcat", "[cstring]")
{
    char str[50]  = "Hello ";
    char str2[50] = "World!";

    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
    etl::strcat(str, str2);
    CHECK(etl::string_view { str } == etl::string_view { "Hello World!" });

    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
    etl::strcat(str, " Goodbye World!");
    CHECK(etl::string_view { str }
          == etl::string_view { "Hello World! Goodbye World!" });
}

TEST_CASE("cstring: strncat", "[cstring]")
{
    char str[50]  = "Hello ";
    char str2[50] = "World!";

    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
    etl::strcat(str, str2);
    CHECK(etl::string_view { str } == etl::string_view { "Hello World!" });
    etl::strncat(str, " Goodbye World!", 3);
    CHECK(etl::string_view { str } == etl::string_view { "Hello World! Go" });
}

TEST_CASE("cstring: strncmp", "[cstring]")
{
    CHECK(etl::strncmp("Hello, world!", "Hello, everybody!", 13) > 0);
    CHECK(etl::strncmp("Hello, everybody!", "Hello, world!", 13) < 0);
    CHECK(etl::strncmp("Hello, everybody!", "Hello, world!", 7) == 0);
}

TEST_CASE("cstring: strchr", "[cstring]")
{
    auto const* txt = "Hello";
    CHECK(etl::strchr(txt, '0') == nullptr);
    CHECK(etl::strchr(txt, 'H') == txt);
    CHECK(etl::strchr(txt, 'e') == etl::next(txt, 1));
    CHECK(etl::strchr(txt, 'l') == etl::next(txt, 2));
    CHECK(etl::strchr(txt, 'l') == etl::next(txt, 2));
    CHECK(etl::strchr(txt, 'o') == etl::next(txt, 4));
    CHECK(etl::strchr(txt, '\0') == etl::next(txt, 5));

    auto str = etl::static_string<16> { "Hello" };
    CHECK(etl::strchr(str.data(), '0') == nullptr);
    CHECK(etl::strchr(str.data(), 'H') == str.data());
    CHECK(etl::strchr(str.data(), 'e') == etl::next(str.data(), 1));
    CHECK(etl::strchr(str.data(), 'l') == etl::next(str.data(), 2));
    CHECK(etl::strchr(str.data(), 'l') == etl::next(str.data(), 2));
    CHECK(etl::strchr(str.data(), 'o') == etl::next(str.data(), 4));
    CHECK(etl::strchr(str.data(), '\0') == etl::next(str.data(), 5));
}

TEST_CASE("cstring: strrchr", "[cstring]")
{
    auto const* txt = "Hello";
    CHECK(etl::strrchr(txt, '0') == nullptr);
    CHECK(etl::strrchr(txt, 'H') == txt);
    CHECK(etl::strrchr(txt, 'e') == etl::next(txt, 1));
    CHECK(etl::strrchr(txt, 'l') == etl::next(txt, 3));
    CHECK(etl::strrchr(txt, 'l') == etl::next(txt, 3));
    CHECK(etl::strrchr(txt, 'o') == etl::next(txt, 4));
    CHECK(etl::strrchr(txt, '\0') == etl::next(txt, 5));

    auto str = etl::static_string<16> { "Hello" };
    CHECK(etl::strrchr(str.data(), '0') == nullptr);
    CHECK(etl::strrchr(str.data(), 'H') == str.data());
    CHECK(etl::strrchr(str.data(), 'e') == etl::next(str.data(), 1));
    CHECK(etl::strrchr(str.data(), 'l') == etl::next(str.data(), 3));
    CHECK(etl::strrchr(str.data(), 'l') == etl::next(str.data(), 3));
    CHECK(etl::strrchr(str.data(), 'o') == etl::next(str.data(), 4));
    CHECK(etl::strrchr(str.data(), '\0') == etl::next(str.data(), 5));
}

TEST_CASE("cstring: strspn", "[cstring]")
{
    auto const* lowAlpha = "qwertyuiopasdfghjklzxcvbnm";
    auto const str       = etl::static_string<16> { "abcde312$#@" };
    auto const span      = etl::strspn(str.c_str(), lowAlpha);
    REQUIRE(str.substr(span) == "312$#@");
}

TEST_CASE("cstring: strcspn", "[cstring]")
{
    auto const* invalid = "*$#";
    auto const str      = etl::static_string<16> { "abcde312$#@" };
    REQUIRE(etl::strcspn(str.c_str(), invalid) == 8);
}

TEST_CASE("cstring: memcpy", "[cstring]")
{
    auto source = etl::array<etl::uint8_t, 2> {};
    source[0]   = 1;
    source[1]   = 2;
    REQUIRE(source.at(0) == 1);
    REQUIRE(source.at(1) == 2);

    auto destination = etl::array<etl::uint8_t, 2> {};
    REQUIRE(destination.at(0) == 0);
    REQUIRE(destination.at(1) == 0);

    etl::memcpy(destination.data(), source.data(), source.size());
    REQUIRE(source.at(0) == 1);
    REQUIRE(source.at(1) == 2);
    REQUIRE(destination.at(0) == 1);
    REQUIRE(destination.at(1) == 2);
}

TEST_CASE("cstring: memset", "[cstring]")
{
    auto buffer = etl::array<etl::uint8_t, 2> {};
    REQUIRE(buffer.at(0) == 0);
    REQUIRE(buffer.at(1) == 0);

    etl::memset(buffer.data(), 1, buffer.size());
    REQUIRE(buffer.at(0) == 1);
    REQUIRE(buffer.at(1) == 1);
}

TEST_CASE("cstring: strlen", "[cstring]")
{
    REQUIRE(etl::strlen("") == 0);
    REQUIRE(etl::strlen("a") == 1);
    REQUIRE(etl::strlen("to") == 2);
    REQUIRE(etl::strlen("xxxxxxxxxx") == 10);
}
