// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/string_view.hpp>

#include <cstdio>
#include <string>

// auto fuzz_string_view_compare(FuzzedDataProvider& p) -> int
// {
//     auto sign = [](int x) { return x == 0 ? 0 : (x < 0 ? -1 : 1); };

// auto const a = p.ConsumeRandomLengthString(64);
// auto const b = p.ConsumeRandomLengthString(64);

// auto const eview = etl::string_view{a.data(), a.size()};
// auto const sview = std::string_view{a.data(), a.size()};

// auto const ecmp = eview.compare(b.c_str());
// auto const scmp = sview.compare(b.c_str());

// if (sign(ecmp) != sign(scmp)) {
//     std::printf("etl::string_view::compare\n");
//     std::printf("this: '%s' str: '%s'\n", a.c_str(), b.c_str());
//     std::printf("len(this): '%zu' len(str): '%zu'\n", a.size(), b.size());
//     std::printf("ecmp: '%d' scmp: '%d'\n", ecmp, scmp);
//     return 1;
// }
// return 0;
// }

auto fuzz_string_view_find(FuzzedDataProvider& p) -> int
{
    auto const haystack = p.ConsumeRandomLengthString(64);
    auto const needle   = p.ConsumeRandomLengthString(64);

    auto const eview = etl::string_view{haystack.data(), haystack.size()};
    auto const sview = std::string_view{haystack.data(), haystack.size()};

    auto const epos = eview.find(needle.c_str());
    auto const spos = sview.find(needle.c_str());
    if (epos != spos) {
        std::printf("etl::string_view::find\n");
        std::printf("haystack: '%s' needle: '%s'\n", haystack.c_str(), needle.c_str());
        std::printf("epos: '%zu' spos: '%zu'\n", epos, spos);
        return 1;
    }
    return 0;
}

auto fuzz_string_view_rfind(FuzzedDataProvider& p) -> int
{
    auto const haystack = p.ConsumeRandomLengthString(64);
    auto const needle   = p.ConsumeRandomLengthString(64);

    auto const eview = etl::string_view{haystack.data(), haystack.size()};
    auto const sview = std::string_view{haystack.data(), haystack.size()};

    auto const epos = eview.rfind(needle.c_str());
    auto const spos = sview.rfind(needle.c_str());
    if (epos != spos) {
        std::printf("etl::string_view::rfind\n");
        std::printf("haystack: '%s' needle: '%s'\n", haystack.c_str(), needle.c_str());
        std::printf("epos: '%zu' spos: '%zu'\n", epos, spos);
        return 1;
    }
    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    if (size == 0) {
        return 0;
    }
    auto p = FuzzedDataProvider{data, size};
    // RUN(fuzz_string_view_compare(p));
    RUN(fuzz_string_view_find(p));
    RUN(fuzz_string_view_rfind(p));
    return 0;
}
