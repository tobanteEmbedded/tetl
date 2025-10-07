// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/cstring.hpp>
#include <etl/iterator.hpp>
#include <etl/string.hpp>

#include <string>

[[nodiscard]] static auto test_string(FuzzedDataProvider& p) -> int
{
    auto const chars = p.ConsumeBytesWithTerminator<char>(127, 0);

    auto etlString = etl::inplace_string<128>{};
    etl::copy(chars.begin(), chars.end(), etl::back_inserter(etlString));

    auto stdString = std::string{chars.begin(), chars.end()};

    if (etlString.size() != stdString.size()) {
        return 1;
    }
    if (etl::strlen(chars.data()) != std::strlen(chars.data())) {
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

    RUN(test_string(p));

    return 0;
}
