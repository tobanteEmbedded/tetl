// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/span.hpp>

#include <algorithm>

[[nodiscard]] auto fuzz_partition(FuzzedDataProvider& p) -> int
{
    auto ebytes = p.ConsumeRemainingBytes<unsigned char>();
    auto sbytes = ebytes;

    auto const eview = etl::span<unsigned char>{ebytes.data(), ebytes.size()};
    auto const sview = etl::span<unsigned char>{sbytes.data(), sbytes.size()};

    auto const predicate = [](unsigned char x) -> bool { return x < 42; };
    auto const e         = etl::partition(eview.begin(), eview.end(), predicate);
    auto const s         = std::partition(sview.begin(), sview.end(), predicate);
    if (std::distance(eview.begin(), e) != std::distance(sview.begin(), s)) {
        return 1;
    }

    if (not etl::is_partitioned(eview.begin(), eview.end(), predicate)) {
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_partition(p));
    return 0;
}
