// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/charconv.hpp>
#include <etl/system_error.hpp>

#include <charconv>
#include <map>
#include <print>
#include <stdexcept>
#include <string>
#include <system_error>

template <typename IntType>
[[nodiscard]] static auto test_from_chars(FuzzedDataProvider& p) -> int
{
    using namespace etl::fuzzing;

    auto const base  = p.ConsumeIntegralInRange<int>(2, 36);
    auto const input = p.ConsumeRandomLengthString();

    auto [stdVal, stdPtr, stdEc] = [base, &input] {
        auto val       = IntType{};
        auto [ptr, ec] = std::from_chars(input.c_str(), input.c_str() + input.size(), val, base);
        return std::make_tuple(val, ptr, ec);
    }();

    auto [etlVal, etlPtr, etlEc] = [base, &input] {
        auto val       = IntType{};
        auto [ptr, ec] = to_std(etl::from_chars(input.c_str(), input.c_str() + input.size(), val, base));
        return std::make_tuple(val, ptr, ec);
    }();

    if (etlVal != stdVal) {
        std::println(stderr, "Str: '{}' Base: {} Value mismatch: etl={} - std={}", input, base, etlVal, stdVal);
        return 1;
    }

    if (etlEc != stdEc) {
        std::println(
            stderr,
            "Str: '{}' Base: {} Error mismatch: etl={} - std={}",
            input,
            base,
            to_string(etlEc),
            to_string(stdEc)
        );
        return 1;
    }

    if (etlPtr != stdPtr) {
        std::println(
            stderr,
            "Str: '{}' Base: {} Value: etl={} - std={} Error: etl={} - std={} Pointer mismatch: etl={} - std={}",
            input,
            base,
            etlVal,
            stdVal,
            to_string(etlEc),
            to_string(stdEc),
            std::distance(input.data(), etlPtr),
            std::distance(input.data(), stdPtr)
        );
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

    RUN(test_from_chars<etl::uint8_t>(p));
    RUN(test_from_chars<etl::int8_t>(p));

    RUN(test_from_chars<etl::uint16_t>(p));
    RUN(test_from_chars<etl::int16_t>(p));

    RUN(test_from_chars<etl::uint32_t>(p));
    RUN(test_from_chars<etl::int32_t>(p));

    RUN(test_from_chars<etl::uint64_t>(p));
    RUN(test_from_chars<etl::int64_t>(p));

    return 0;
}
