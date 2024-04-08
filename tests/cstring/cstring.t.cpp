// SPDX-License-Identifier: BSL-1.0

#include <etl/cstring.hpp>

#include <etl/array.hpp>
#include <etl/string.hpp>
#include <etl/string_view.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

using namespace etl::literals;

constexpr auto test_str() -> bool
{
    // "cstring: strcpy"
    {
        char source[32] = {"test"};
        char dest[32]{};

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcpy(dest, source);

        CHECK(etl::strlen(dest) == 4);
    }

    // "cstring: strncpy"
    {
        char source[32] = {"test"};
        char dest[32]{};
        etl::strncpy(dest, source, 2);
        CHECK(dest[0] == 't');
        CHECK(dest[1] == 'e');
    }

    // "cstring: strcat"
    {
        char str[50]  = "Hello ";
        char str2[50] = "World!";

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcat(str, str2);
        CHECK(etl::string_view{str} == "Hello World!"_sv);

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcat(str, " Goodbye World!");
        CHECK(etl::string_view{str} == "Hello World! Goodbye World!"_sv);
    }

    // "cstring: strncat"
    {
        char str[50]  = "Hello ";
        char str2[50] = "World!";

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcat(str, str2);
        CHECK(etl::string_view{str} == "Hello World!"_sv);
        etl::strncat(str, " Goodbye World!", 3);
        CHECK(etl::string_view{str} == "Hello World! Go"_sv);
    }

    // "cstring: strncmp"
    {
        CHECK(etl::strncmp("Hello, world!", "Hello, everybody!", 13) > 0);
        CHECK(etl::strncmp("Hello, everybody!", "Hello, world!", 13) < 0);
        CHECK(etl::strncmp("Hello, everybody!", "Hello, world!", 7) == 0);
    }

    // "cstring: strchr"
    {
        auto const* txt = "Hello";
        CHECK(etl::strchr(txt, '0') == nullptr);
        CHECK(etl::strchr(txt, 'H') == txt);
        CHECK(etl::strchr(txt, 'e') == etl::next(txt, 1));
        CHECK(etl::strchr(txt, 'l') == etl::next(txt, 2));
        CHECK(etl::strchr(txt, 'l') == etl::next(txt, 2));
        CHECK(etl::strchr(txt, 'o') == etl::next(txt, 4));
        CHECK(etl::strchr(txt, '\0') == etl::next(txt, 5));

        auto str = etl::inplace_string<16>{"Hello"};
        CHECK(etl::strchr(str.data(), '0') == nullptr);
        CHECK(etl::strchr(str.data(), 'H') == str.data());
        CHECK(etl::strchr(str.data(), 'e') == etl::next(str.data(), 1));
        CHECK(etl::strchr(str.data(), 'l') == etl::next(str.data(), 2));
        CHECK(etl::strchr(str.data(), 'l') == etl::next(str.data(), 2));
        CHECK(etl::strchr(str.data(), 'o') == etl::next(str.data(), 4));
        CHECK(etl::strchr(str.data(), '\0') == etl::next(str.data(), 5));
    }

    // "cstring: strrchr"
    {
        auto const* txt = "Hello";
        CHECK(etl::strrchr(txt, '0') == nullptr);
        CHECK(etl::strrchr(txt, 'H') == txt);
        CHECK(etl::strrchr(txt, 'e') == etl::next(txt, 1));
        CHECK(etl::strrchr(txt, 'l') == etl::next(txt, 3));
        CHECK(etl::strrchr(txt, 'l') == etl::next(txt, 3));
        CHECK(etl::strrchr(txt, 'o') == etl::next(txt, 4));
        CHECK(etl::strrchr(txt, '\0') == etl::next(txt, 5));

        auto str = etl::inplace_string<16>{"Hello"};
        CHECK(etl::strrchr(str.data(), '0') == nullptr);
        CHECK(etl::strrchr(str.data(), 'H') == str.data());
        CHECK(etl::strrchr(str.data(), 'e') == etl::next(str.data(), 1));
        CHECK(etl::strrchr(str.data(), 'l') == etl::next(str.data(), 3));
        CHECK(etl::strrchr(str.data(), 'l') == etl::next(str.data(), 3));
        CHECK(etl::strrchr(str.data(), 'o') == etl::next(str.data(), 4));
        CHECK(etl::strrchr(str.data(), '\0') == etl::next(str.data(), 5));
    }

    // "cstring: strspn"
    {
        auto const* lowAlpha = "qwertyuiopasdfghjklzxcvbnm";
        auto const str       = etl::inplace_string<16>{"abcde312$#@"};
        auto const span      = etl::strspn(str.c_str(), lowAlpha);
        CHECK(str.substr(span) == "312$#@");
    }

    // "cstring: strcspn"
    {
        auto const* invalid = "*$#";
        auto const str      = etl::inplace_string<16>{"abcde312$#@"};
        CHECK(etl::strcspn(str.c_str(), invalid) == 8);
    }

    // "cstring: strlen"
    {
        CHECK(etl::strlen("") == 0);
        CHECK(etl::strlen("a") == 1);
        CHECK(etl::strlen("to") == 2);
        CHECK(etl::strlen("xxxxxxxxxx") == 10);
    }

    return true;
}

static auto test_mem() -> bool
{
    // "cstring: memcpy"
    {
        auto source = etl::array<etl::uint8_t, 2>{};
        source[0]   = 1;
        source[1]   = 2;
        CHECK(source[0] == 1);
        CHECK(source[1] == 2);

        auto destination = etl::array<etl::uint8_t, 2>{};
        CHECK(destination[0] == 0);
        CHECK(destination[1] == 0);

        etl::memcpy(destination.data(), source.data(), source.size());
        CHECK(source[0] == 1);
        CHECK(source[1] == 2);
        CHECK(destination[0] == 1);
        CHECK(destination[1] == 2);
    }

    // "cstring: memset"
    {
        auto buffer = etl::array<etl::uint8_t, 2>{};
        CHECK(buffer[0] == 0);
        CHECK(buffer[1] == 0);

        etl::memset(buffer.data(), 1, buffer.size());
        CHECK(buffer[0] == 1);
        CHECK(buffer[1] == 1);
    }

    return true;
}

auto main() -> int
{
    CHECK(test_str());
    static_assert(test_str());

    CHECK(test_mem());
    return 0;
}
