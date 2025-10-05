// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/string_view.hpp>

#include <print>
#include <string_view>

static auto fuzz_string_view_rfind(FuzzedDataProvider& p) -> int
{
    auto const haystack = p.ConsumeRandomLengthString();
    auto const needle   = p.ConsumeRandomLengthString();

    auto const eview = etl::string_view{haystack.data(), haystack.size()};
    auto const sview = std::string_view{haystack.data(), haystack.size()};

    if (not needle.empty()) {
        auto const epos = eview.rfind(needle[0]);
        auto const spos = sview.rfind(needle[0]);
        if (epos != spos) {
            std::println(stderr, "etl::string_view::rfind(char)");
            std::println(stderr, "haystack: '{}' needle: '{}'", haystack, needle);
            std::println(stderr, "epos: '{}' spos: '{}'", epos, spos);
            return 1;
        }
    }

    auto const epos = eview.rfind(needle.c_str());
    auto const spos = sview.rfind(needle.c_str());
    if (epos != spos) {
        std::println(stderr, "etl::string_view::rfind(char const*)");
        std::println(stderr, "haystack: '{}' needle: '{}'", haystack, needle);
        std::println(stderr, "epos: '{}' spos: '{}'", epos, spos);
        return 1;
    }
    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_string_view_rfind(p));
    return 0;
}
