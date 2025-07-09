// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.cstddef;
import etl.string;
import etl.utility;
#else
    #include <etl/cstddef.hpp>
    #include <etl/string.hpp>
    #include <etl/utility.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    {
        auto count = etl::size_t(0);
        CHECK(etl::stoi(T{"0"}, &count, 10) == 0);
        CHECK(count == 1);
    }

    {
        auto count = etl::size_t(0);
        CHECK(etl::stoi(T{" 123 "}, &count, 10) == 123);
        CHECK(count == 4);
    }

    CHECK(etl::stoi(T{" 0"}) == 0);
    CHECK(etl::stoi(T{" 0 "}) == 0);
    CHECK(etl::stoi(T{"1"}) == 1);
    CHECK(etl::stoi(T{"-1"}) == -1);
    CHECK(etl::stoi(T{" -1"}) == -1);
    CHECK(etl::stoi(T{" -1 "}) == -1);
    CHECK(etl::stoi(T{"2"}) == 2);
    CHECK(etl::stoi(T{"3"}) == 3);
    CHECK(etl::stoi(T{"4"}) == 4);
    CHECK(etl::stoi(T{"5"}) == 5);
    CHECK(etl::stoi(T{"6"}) == 6);
    CHECK(etl::stoi(T{"7"}) == 7);
    CHECK(etl::stoi(T{"8"}) == 8);
    CHECK(etl::stoi(T{"9"}) == 9);
    CHECK(etl::stoi(T{"10"}) == 10);
    CHECK(etl::stoi(T{"11"}) == 11);
    CHECK(etl::stoi(T{"99"}) == 99);
    CHECK(etl::stoi(T{"11123"}) == 11123);
    CHECK(etl::stoi(T{" 11123"}) == 11123);
    CHECK(etl::stoi(T{" 11123 "}) == 11123);

    CHECK(etl::stol(T{"0"}) == 0L);
    CHECK(etl::stol(T{"1"}) == 1L);
    CHECK(etl::stol(T{"2"}) == 2L);
    CHECK(etl::stol(T{"3"}) == 3L);
    CHECK(etl::stol(T{"4"}) == 4L);
    CHECK(etl::stol(T{"5"}) == 5L);
    CHECK(etl::stol(T{"6"}) == 6L);
    CHECK(etl::stol(T{"7"}) == 7L);
    CHECK(etl::stol(T{"8"}) == 8L);
    CHECK(etl::stol(T{"9"}) == 9L);
    CHECK(etl::stol(T{"10"}) == 10L);
    CHECK(etl::stol(T{"11"}) == 11L);
    CHECK(etl::stol(T{"99"}) == 99L);
    CHECK(etl::stol(T{"11123"}) == 11123L);

    CHECK(etl::stoll(T{"0"}) == 0LL);
    CHECK(etl::stoll(T{"1"}) == 1LL);
    CHECK(etl::stoll(T{"2"}) == 2LL);
    CHECK(etl::stoll(T{"3"}) == 3LL);
    CHECK(etl::stoll(T{"4"}) == 4LL);
    CHECK(etl::stoll(T{"5"}) == 5LL);
    CHECK(etl::stoll(T{"6"}) == 6LL);
    CHECK(etl::stoll(T{"7"}) == 7LL);
    CHECK(etl::stoll(T{"8"}) == 8LL);
    CHECK(etl::stoll(T{"9"}) == 9LL);
    CHECK(etl::stoll(T{"10"}) == 10LL);
    CHECK(etl::stoll(T{"11"}) == 11LL);
    CHECK(etl::stoll(T{"99"}) == 99LL);
    CHECK(etl::stoll(T{"11123"}) == 11123LL);

    CHECK(etl::stoul(T{"0"}) == 0UL);
    CHECK(etl::stoul(T{"1"}) == 1UL);
    CHECK(etl::stoul(T{"2"}) == 2UL);
    CHECK(etl::stoul(T{"3"}) == 3UL);
    CHECK(etl::stoul(T{"4"}) == 4UL);
    CHECK(etl::stoul(T{"5"}) == 5UL);
    CHECK(etl::stoul(T{"6"}) == 6UL);
    CHECK(etl::stoul(T{"7"}) == 7UL);
    CHECK(etl::stoul(T{"8"}) == 8UL);
    CHECK(etl::stoul(T{"9"}) == 9UL);
    CHECK(etl::stoul(T{"10"}) == 10UL);
    CHECK(etl::stoul(T{"11"}) == 11UL);
    CHECK(etl::stoul(T{"99"}) == 99UL);
    CHECK(etl::stoul(T{"11123"}) == 11123UL);

    CHECK(etl::stoull(T{"0"}) == 0ULL);
    CHECK(etl::stoull(T{"1"}) == 1ULL);
    CHECK(etl::stoull(T{"2"}) == 2ULL);
    CHECK(etl::stoull(T{"3"}) == 3ULL);
    CHECK(etl::stoull(T{"4"}) == 4ULL);
    CHECK(etl::stoull(T{"5"}) == 5ULL);
    CHECK(etl::stoull(T{"6"}) == 6ULL);
    CHECK(etl::stoull(T{"7"}) == 7ULL);
    CHECK(etl::stoull(T{"8"}) == 8ULL);
    CHECK(etl::stoull(T{"9"}) == 9ULL);
    CHECK(etl::stoull(T{"10"}) == 10ULL);
    CHECK(etl::stoull(T{"11"}) == 11ULL);
    CHECK(etl::stoull(T{"99"}) == 99ULL);
    CHECK(etl::stoull(T{"11123"}) == 11123ULL);

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<etl::inplace_string<16>>());
    CHECK(test<etl::inplace_string<17>>());
    CHECK(test<etl::inplace_string<18>>());
    CHECK(test<etl::inplace_string<24>>());
    CHECK(test<etl::inplace_string<32>>());
    CHECK(test<etl::inplace_string<64>>());
    CHECK(test<etl::inplace_string<128>>());
    CHECK(test<etl::inplace_string<256>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
