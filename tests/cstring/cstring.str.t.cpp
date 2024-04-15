// SPDX-License-Identifier: BSL-1.0

#include <etl/cstring.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/string.hpp>
#include <etl/string_view.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

using namespace etl::literals;

constexpr auto test() -> bool
{
    // strcpy
    {
        char source[32] = {"test"};
        char dest[32]{};

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcpy(dest, source);

        CHECK(etl::strlen(dest) == 4);
    }

    // strncpy
    {
        char source[32] = {"test"};
        char dest[32]{};
        etl::strncpy(dest, source, 2);
        CHECK(dest[0] == 't');
        CHECK(dest[1] == 'e');
    }

    // strcat
    {
        char str[50]  = "Hello ";
        char str2[50] = "World!";

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcat(str, str2);
        CHECK(str == "Hello World!"_sv);

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcat(str, " Goodbye World!");
        CHECK(str == "Hello World! Goodbye World!"_sv);
    }

    // strncat
    {
        char str[50]  = "Hello ";
        char str2[50] = "World!";

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcat(str, str2);
        CHECK(str == "Hello World!"_sv);
        etl::strncat(str, " Goodbye World!", 3);
        CHECK(str == "Hello World! Go"_sv);
    }

    // strncmp
    {
        CHECK(etl::strncmp("Hello, world!", "Hello, everybody!", 13) > 0);
        CHECK(etl::strncmp("Hello, everybody!", "Hello, world!", 13) < 0);
        CHECK(etl::strncmp("Hello, everybody!", "Hello, world!", 7) == 0);
        CHECK(etl::strncmp("Hello, wo", "Hello, world!", 8) == 0);
        CHECK(etl::strncmp("Hello, wo", "Hello, world!", 9) == 0);
    }

    // strchr
    {
        CHECK(etl::strchr(static_cast<char*>(nullptr), '0') == nullptr);
        CHECK(etl::strchr(static_cast<char const*>(nullptr), '0') == nullptr);

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

    // strrchr
    {
        CHECK(etl::strrchr(static_cast<char*>(nullptr), '0') == nullptr);
        CHECK(etl::strrchr(static_cast<char const*>(nullptr), '0') == nullptr);

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

    // strspn
    {
        auto const* lowAlpha = "qwertyuiopasdfghjklzxcvbnm";
        auto const str       = etl::inplace_string<16>{"abcde312$#@"};
        auto const span      = etl::strspn(str.c_str(), lowAlpha);
        CHECK(str.substr(span) == "312$#@");
    }

    // strcspn
    {
        auto const* invalid = "*$#";
        auto const str      = etl::inplace_string<16>{"abcde312$#@"};
        CHECK(etl::strcspn(str.c_str(), invalid) == 8);
    }

    // strpbrk
    {
        auto const* space = " ";
        auto const* comma = ";,";
        auto str          = etl::inplace_string<16>{"hello world,"};

        CHECK(etl::strpbrk(str.c_str(), space) == etl::next(str.c_str(), 5));
        CHECK(etl::strpbrk(str.c_str(), comma) == etl::next(str.c_str(), 11));

        auto const& cstr = str;
        CHECK(etl::strpbrk(cstr.c_str(), space) == etl::next(cstr.c_str(), 5));
        CHECK(etl::strpbrk(cstr.c_str(), comma) == etl::next(cstr.c_str(), 11));

        // TODO
        // auto const* dollar = "$";
        // CHECK(etl::strpbrk(str.c_str(), dollar) == nullptr);
        // CHECK(etl::strpbrk(cstr.c_str(), dollar) == nullptr);
    }

    // strlen
    {
        CHECK(etl::strlen("") == 0);
        CHECK(etl::strlen("a") == 1);
        CHECK(etl::strlen("to") == 2);
        CHECK(etl::strlen("xxxxxxxxxx") == 10);
    }

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
