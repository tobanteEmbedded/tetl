// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/cctype.hpp>

#include <cctype>
#include <print>

[[nodiscard]] static auto fuzz_isalpha(FuzzedDataProvider& p) -> int
{
    auto const c = p.ConsumeIntegral<char>();

    {
        auto const s = std::isalnum(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::isalnum(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::isalnum({:c}) = {}", c, s);
            std::println(stderr, "etl::isalnum({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::isalpha(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::isalpha(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::isalpha({:c}) = {}", c, s);
            std::println(stderr, "etl::isalpha({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::isblank(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::isblank(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::isblank({:c}) = {}", c, s);
            std::println(stderr, "etl::isblank({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::iscntrl(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::iscntrl(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::iscntrl({:c}) = {}", c, s);
            std::println(stderr, "etl::iscntrl({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::isdigit(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::isdigit(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::isdigit({:c}) = {}", c, s);
            std::println(stderr, "etl::isdigit({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::isgraph(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::isgraph(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::isgraph({:c}) = {}", c, s);
            std::println(stderr, "etl::isgraph({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::islower(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::islower(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::islower({:c}) = {}", c, s);
            std::println(stderr, "etl::islower({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::isprint(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::isprint(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::isprint({:c}) = {}", c, s);
            std::println(stderr, "etl::isprint({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::ispunct(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::ispunct(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::ispunct({:c}) = {}", c, s);
            std::println(stderr, "etl::ispunct({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::isspace(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::isspace(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::isspace({:c}) = {}", c, s);
            std::println(stderr, "etl::isspace({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::isupper(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::isupper(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::isupper({:c}) = {}", c, s);
            std::println(stderr, "etl::isupper({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::isxdigit(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        auto const e = etl::isxdigit(static_cast<int>(static_cast<unsigned char>(c))) != 0;
        if (e != s) {
            std::println(stderr, "std::isxdigit({:c}) = {}", c, s);
            std::println(stderr, "etl::isxdigit({:c}) = {}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::tolower(static_cast<int>(static_cast<unsigned char>(c)));
        auto const e = etl::tolower(static_cast<int>(static_cast<unsigned char>(c)));
        if (e != s) {
            std::println(stderr, "std::tolower({:c}) = {:c}", c, s);
            std::println(stderr, "etl::tolower({:c}) = {:c}", c, e);
            return 1;
        }
    }

    {
        auto const s = std::toupper(static_cast<int>(static_cast<unsigned char>(c)));
        auto const e = etl::toupper(static_cast<int>(static_cast<unsigned char>(c)));
        if (e != s) {
            std::println(stderr, "std::toupper({:c}) = {:c}", c, s);
            std::println(stderr, "etl::toupper({:c}) = {:c}", c, e);
            return 1;
        }
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_isalpha(p));
    return 0;
}
