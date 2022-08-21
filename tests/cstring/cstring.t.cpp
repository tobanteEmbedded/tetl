/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cstring.hpp"

#include "etl/array.hpp"
#include "etl/string.hpp"
#include "etl/string_view.hpp"

#include "testing/testing.hpp"

using namespace etl::literals;
using etl::string_view;

constexpr auto test() -> bool
{
    // "cstring: strcpy"
    {
        char source[32] = { "test" };
        char dest[32] {};

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcpy(dest, source);

        assert((etl::strlen(dest) == 4));
    }

    // "cstring: strncpy"
    {
        char source[32] = { "test" };
        char dest[32] {};
        etl::strncpy(dest, source, 2);
        assert((dest[0] == 't'));
        assert((dest[1] == 'e'));
    }

    // "cstring: strcat"
    {
        char str[50]  = "Hello ";
        char str2[50] = "World!";

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcat(str, str2);
        assert((string_view { str } == "Hello World!"_sv));

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcat(str, " Goodbye World!");
        assert((string_view { str } == "Hello World! Goodbye World!"_sv));
    }

    // "cstring: strncat"
    {
        char str[50]  = "Hello ";
        char str2[50] = "World!";

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
        etl::strcat(str, str2);
        assert((string_view { str } == "Hello World!"_sv));
        etl::strncat(str, " Goodbye World!", 3);
        assert((string_view { str } == "Hello World! Go"_sv));
    }

    // "cstring: strncmp"
    {
        assert((etl::strncmp("Hello, world!", "Hello, everybody!", 13) > 0));
        assert((etl::strncmp("Hello, everybody!", "Hello, world!", 13) < 0));
        assert((etl::strncmp("Hello, everybody!", "Hello, world!", 7) == 0));
    }

    // "cstring: strchr"
    {
        auto const* txt = "Hello";
        assert((etl::strchr(txt, '0') == nullptr));
        assert((etl::strchr(txt, 'H') == txt));
        assert((etl::strchr(txt, 'e') == etl::next(txt, 1)));
        assert((etl::strchr(txt, 'l') == etl::next(txt, 2)));
        assert((etl::strchr(txt, 'l') == etl::next(txt, 2)));
        assert((etl::strchr(txt, 'o') == etl::next(txt, 4)));
        assert((etl::strchr(txt, '\0') == etl::next(txt, 5)));

        auto str = etl::static_string<16> { "Hello" };
        assert((etl::strchr(str.data(), '0') == nullptr));
        assert((etl::strchr(str.data(), 'H') == str.data()));
        assert((etl::strchr(str.data(), 'e') == etl::next(str.data(), 1)));
        assert((etl::strchr(str.data(), 'l') == etl::next(str.data(), 2)));
        assert((etl::strchr(str.data(), 'l') == etl::next(str.data(), 2)));
        assert((etl::strchr(str.data(), 'o') == etl::next(str.data(), 4)));
        assert((etl::strchr(str.data(), '\0') == etl::next(str.data(), 5)));
    }

    // "cstring: strrchr"
    {
        auto const* txt = "Hello";
        assert((etl::strrchr(txt, '0') == nullptr));
        assert((etl::strrchr(txt, 'H') == txt));
        assert((etl::strrchr(txt, 'e') == etl::next(txt, 1)));
        assert((etl::strrchr(txt, 'l') == etl::next(txt, 3)));
        assert((etl::strrchr(txt, 'l') == etl::next(txt, 3)));
        assert((etl::strrchr(txt, 'o') == etl::next(txt, 4)));
        assert((etl::strrchr(txt, '\0') == etl::next(txt, 5)));

        auto str = etl::static_string<16> { "Hello" };
        assert((etl::strrchr(str.data(), '0') == nullptr));
        assert((etl::strrchr(str.data(), 'H') == str.data()));
        assert((etl::strrchr(str.data(), 'e') == etl::next(str.data(), 1)));
        assert((etl::strrchr(str.data(), 'l') == etl::next(str.data(), 3)));
        assert((etl::strrchr(str.data(), 'l') == etl::next(str.data(), 3)));
        assert((etl::strrchr(str.data(), 'o') == etl::next(str.data(), 4)));
        assert((etl::strrchr(str.data(), '\0') == etl::next(str.data(), 5)));
    }

    // "cstring: strspn"
    {
        auto const* lowAlpha = "qwertyuiopasdfghjklzxcvbnm";
        auto const str       = etl::static_string<16> { "abcde312$#@" };
        auto const span      = etl::strspn(str.c_str(), lowAlpha);
        assert(str.substr(span) == "312$#@");
    }

    // "cstring: strcspn"
    {
        auto const* invalid = "*$#";
        auto const str      = etl::static_string<16> { "abcde312$#@" };
        assert(etl::strcspn(str.c_str(), invalid) == 8);
    }

    // "cstring: memcpy"
    {
        auto source = etl::array<etl::uint8_t, 2> {};
        source[0]   = 1;
        source[1]   = 2;
        assert(source.at(0) == 1);
        assert(source.at(1) == 2);

        auto destination = etl::array<etl::uint8_t, 2> {};
        assert(destination.at(0) == 0);
        assert(destination.at(1) == 0);

        etl::memcpy(destination.data(), source.data(), source.size());
        assert(source.at(0) == 1);
        assert(source.at(1) == 2);
        assert(destination.at(0) == 1);
        assert(destination.at(1) == 2);
    }

    // "cstring: memset"
    {
        auto buffer = etl::array<etl::uint8_t, 2> {};
        assert(buffer.at(0) == 0);
        assert(buffer.at(1) == 0);

        etl::memset(buffer.data(), 1, buffer.size());
        assert(buffer.at(0) == 1);
        assert(buffer.at(1) == 1);
    }

    // "cstring: strlen"
    {
        assert(etl::strlen("") == 0);
        assert(etl::strlen("a") == 1);
        assert(etl::strlen("to") == 2);
        assert(etl::strlen("xxxxxxxxxx") == 10);
    }

    return true;
}

auto main() -> int
{
    assert(test());
    // static_assert(test());

    // TODO: [tobi] Add constexpr tests
    return 0;
}