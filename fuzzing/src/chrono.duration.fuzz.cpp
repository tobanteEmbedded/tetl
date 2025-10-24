// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/chrono.hpp>

#include <chrono>
#include <print>

[[nodiscard]] static auto fuzz_duration(FuzzedDataProvider& p) -> int
{
    auto const sec   = p.ConsumeIntegral<short>();
    auto const milli = p.ConsumeIntegral<int>();

    auto const esec = etl::chrono::seconds{sec};
    auto const ssec = std::chrono::seconds{sec};

    auto const emilli = etl::chrono::milliseconds{milli};
    auto const smilli = std::chrono::milliseconds{milli};

    auto const esectp = etl::chrono::sys_time<etl::chrono::seconds>{esec};
    auto const ssectp = std::chrono::sys_time<std::chrono::seconds>{ssec};

    auto const emillitp = etl::chrono::sys_time<etl::chrono::milliseconds>{emilli};
    auto const smillitp = std::chrono::sys_time<std::chrono::milliseconds>{smilli};

    if ((esectp == emillitp) != (ssectp == smillitp)) {
        std::println(stderr, "sec == milli mismatch: {} vs. {}", ssectp, smillitp);
        std::println(stderr, "etl: {}", esectp == emillitp);
        std::println(stderr, "std: {}", ssectp == smillitp);
        return 1;
    }

    if ((esectp != emillitp) != (ssectp != smillitp)) {
        std::println(stderr, "sec != milli mismatch: {} vs. {}", ssectp, smillitp);
        std::println(stderr, "etl: {}", esectp != emillitp);
        std::println(stderr, "std: {}", ssectp != smillitp);
        return 1;
    }

    if ((esectp < emillitp) != (ssectp < smillitp)) {
        std::println(stderr, "sec < milli mismatch: {} vs. {}", ssectp, smillitp);
        std::println(stderr, "etl: {}", esectp < emillitp);
        std::println(stderr, "std: {}", ssectp < smillitp);
        return 1;
    }

    if ((esectp <= emillitp) != (ssectp <= smillitp)) {
        std::println(stderr, "sec <= milli mismatch: {} vs. {}", ssectp, smillitp);
        std::println(stderr, "etl: {}", esectp <= emillitp);
        std::println(stderr, "std: {}", ssectp <= smillitp);
        return 1;
    }

    if ((esectp > emillitp) != (ssectp > smillitp)) {
        std::println(stderr, "sec > milli mismatch: {} vs. {}", ssectp, smillitp);
        std::println(stderr, "etl: {}", esectp > emillitp);
        std::println(stderr, "std: {}", ssectp > smillitp);
        return 1;
    }

    if ((esectp >= emillitp) != (ssectp >= smillitp)) {
        std::println(stderr, "sec >= milli mismatch: {} vs. {}", ssectp, smillitp);
        std::println(stderr, "etl: {}", esectp >= emillitp);
        std::println(stderr, "std: {}", ssectp >= smillitp);
        return 1;
    }

    if ((esec + emilli).count() != (ssec + smilli).count()) {
        std::println(stderr, "sec + milli mismatch: {} vs. {}", ssec, smilli);
        std::println(stderr, "etl: {}", (esec + emilli).count());
        std::println(stderr, "std: {}", (ssec + smilli).count());
        return 1;
    }

    if ((esec - emilli).count() != (ssec - smilli).count()) {
        std::println(stderr, "sec - milli mismatch: {} vs. {}", ssec, smilli);
        std::println(stderr, "etl: {}", (esec - emilli).count());
        std::println(stderr, "std: {}", (ssec - smilli).count());
        return 1;
    }

    if (smilli.count() == 0) {
        return 0;
    }

    if ((esec / emilli) != (ssec / smilli)) {
        std::println(stderr, "sec / milli m {} vs. {}", ssec, smilli);
        std::println(stderr, "etl: {}", esec / emilli);
        std::println(stderr, "std: {}", ssec / smilli);
        return 1;
    }

    if ((esec % emilli).count() != (ssec % smilli).count()) {
        std::println(stderr, "sec % milli m.count() {} vs. {}", ssec, smilli);
        std::println(stderr, "etl: {}", (esec % emilli).count());
        std::println(stderr, "std: {}", (ssec % smilli).count());
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_duration(p));
    return 0;
}
