// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/string_view.hpp>

#include <print>
#include <string_view>

static auto fuzz_string_view_find(FuzzedDataProvider& p) -> int
{
    auto const haystack = p.ConsumeRandomLengthString();
    auto const needle   = p.ConsumeRandomLengthString();

    auto const eview = etl::string_view{haystack.data(), haystack.size()};
    auto const sview = std::string_view{haystack.data(), haystack.size()};

    if (not needle.empty()) {
        auto const epos = eview.find(needle[0]);
        auto const spos = sview.find(needle[0]);
        if (epos != spos) {
            std::println("etl::string_view::find(char)");
            std::println("haystack: '{}' needle: '{}'", haystack, needle);
            std::println("epos: '{}' spos: '{}'", epos, spos);
            return 1;
        }
    }

    auto const epos = eview.find(needle.c_str());
    auto const spos = sview.find(needle.c_str());
    if (epos != spos) {
        std::println("etl::string_view::find(char const*)");
        std::println("haystack: '{}' needle: '{}'", haystack, needle);
        std::println("epos: '{}' spos: '{}'", epos, spos);
        return 1;
    }
    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_string_view_find(p));
    return 0;
}
