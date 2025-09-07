// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/functional.hpp>
#endif

template <typename T>
static auto test() -> bool
{
    auto const buffer = etl::array<T, 4>{T(0), T(1), T(2), T(3)};

    auto hasher32 = etl::fnv1a32{};
    hasher32(buffer.data(), buffer.size() * sizeof(T));
    auto const hash32 = static_cast<etl::uint32_t>(hasher32);
    CHECK(hash32 != 0);

    auto hasher64 = etl::fnv1a64{};
    hasher64(buffer.data(), buffer.size() * sizeof(T));
    auto const hash64 = static_cast<etl::uint64_t>(hasher64);
    CHECK(hash64 != 0);

    return true;
}

static auto test_all() -> bool
{
    CHECK(test<char>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());

    return true;
}

auto main() -> int
{
    CHECK(test_all());
    return 0;
}
