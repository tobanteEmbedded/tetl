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
[[nodiscard]] auto fuzz_to_chars(FuzzedDataProvider& p) -> int
{
    using namespace etl::fuzzing;

    auto const base  = p.ConsumeIntegralInRange<int>(2, 36);
    auto const value = p.ConsumeIntegral<IntType>();

    auto stdBuf          = std::array<char, 8>{};
    auto etlBuf          = std::array<char, 8>{};
    auto [stdPtr, stdEc] = [base, value, buffer = &stdBuf] {
        return std::to_chars(buffer->data(), buffer->data() + buffer->size(), value, base);
    }();

    auto [etlPtr, etlEc] = [base, value, buffer = &etlBuf] {
        return to_std(etl::to_chars(buffer->data(), buffer->data() + buffer->size(), value, base));
    }();

    auto const stdDist = std::distance(stdBuf.data(), stdPtr);
    auto const etlDist = std::distance(etlBuf.data(), etlPtr);

    if ((etlDist != stdDist) or (etlEc != stdEc) or ((etlBuf != stdBuf) and stdEc != std::errc::value_too_large)) {
        std::println("Func: {}", __PRETTY_FUNCTION__);
        std::println("Value: {} Base: {}", value, base);
        std::println(
            "Buffer: etl='{}' - std='{}'",
            std::string_view{etlBuf.data(), etlBuf.size()},
            std::string_view{stdBuf.data(), stdBuf.size()}
        );
        std::println("Distance: etl={} - std={}", etlDist, stdDist);
        std::println("Error: etl='{}' - std='{}'", to_string(etlEc), to_string(stdEc));
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

    RUN(fuzz_to_chars<etl::uint8_t>(p));
    RUN(fuzz_to_chars<etl::int8_t>(p));

    RUN(fuzz_to_chars<etl::uint16_t>(p));
    RUN(fuzz_to_chars<etl::int16_t>(p));

    RUN(fuzz_to_chars<etl::uint32_t>(p));
    RUN(fuzz_to_chars<etl::int32_t>(p));

    RUN(fuzz_to_chars<etl::uint64_t>(p));
    RUN(fuzz_to_chars<etl::int64_t>(p));

    return 0;
}
