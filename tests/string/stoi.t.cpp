/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/string.hpp"

#include "etl/string_view.hpp"

#include "testing/testing.hpp"

using namespace etl::literals;

template <typename T>
constexpr auto test() -> bool
{
    assert((etl::stoi(T { "0" }) == 0));
    assert((etl::stoi(T { "1" }) == 1));
    assert((etl::stoi(T { "2" }) == 2));
    assert((etl::stoi(T { "3" }) == 3));
    assert((etl::stoi(T { "4" }) == 4));
    assert((etl::stoi(T { "5" }) == 5));
    assert((etl::stoi(T { "6" }) == 6));
    assert((etl::stoi(T { "7" }) == 7));
    assert((etl::stoi(T { "8" }) == 8));
    assert((etl::stoi(T { "9" }) == 9));
    assert((etl::stoi(T { "10" }) == 10));
    assert((etl::stoi(T { "11" }) == 11));
    assert((etl::stoi(T { "99" }) == 99));
    assert((etl::stoi(T { "11123" }) == 11123));

    assert((etl::stol(T { "0" }) == 0L));
    assert((etl::stol(T { "1" }) == 1L));
    assert((etl::stol(T { "2" }) == 2L));
    assert((etl::stol(T { "3" }) == 3L));
    assert((etl::stol(T { "4" }) == 4L));
    assert((etl::stol(T { "5" }) == 5L));
    assert((etl::stol(T { "6" }) == 6L));
    assert((etl::stol(T { "7" }) == 7L));
    assert((etl::stol(T { "8" }) == 8L));
    assert((etl::stol(T { "9" }) == 9L));
    assert((etl::stol(T { "10" }) == 10L));
    assert((etl::stol(T { "11" }) == 11L));
    assert((etl::stol(T { "99" }) == 99L));
    assert((etl::stol(T { "11123" }) == 11123L));

    assert((etl::stoll(T { "0" }) == 0LL));
    assert((etl::stoll(T { "1" }) == 1LL));
    assert((etl::stoll(T { "2" }) == 2LL));
    assert((etl::stoll(T { "3" }) == 3LL));
    assert((etl::stoll(T { "4" }) == 4LL));
    assert((etl::stoll(T { "5" }) == 5LL));
    assert((etl::stoll(T { "6" }) == 6LL));
    assert((etl::stoll(T { "7" }) == 7LL));
    assert((etl::stoll(T { "8" }) == 8LL));
    assert((etl::stoll(T { "9" }) == 9LL));
    assert((etl::stoll(T { "10" }) == 10LL));
    assert((etl::stoll(T { "11" }) == 11LL));
    assert((etl::stoll(T { "99" }) == 99LL));
    assert((etl::stoll(T { "11123" }) == 11123LL));

    assert((etl::stoul(T { "0" }) == 0UL));
    assert((etl::stoul(T { "1" }) == 1UL));
    assert((etl::stoul(T { "2" }) == 2UL));
    assert((etl::stoul(T { "3" }) == 3UL));
    assert((etl::stoul(T { "4" }) == 4UL));
    assert((etl::stoul(T { "5" }) == 5UL));
    assert((etl::stoul(T { "6" }) == 6UL));
    assert((etl::stoul(T { "7" }) == 7UL));
    assert((etl::stoul(T { "8" }) == 8UL));
    assert((etl::stoul(T { "9" }) == 9UL));
    assert((etl::stoul(T { "10" }) == 10UL));
    assert((etl::stoul(T { "11" }) == 11UL));
    assert((etl::stoul(T { "99" }) == 99UL));
    assert((etl::stoul(T { "11123" }) == 11123UL));

    assert((etl::stoull(T { "0" }) == 0ULL));
    assert((etl::stoull(T { "1" }) == 1ULL));
    assert((etl::stoull(T { "2" }) == 2ULL));
    assert((etl::stoull(T { "3" }) == 3ULL));
    assert((etl::stoull(T { "4" }) == 4ULL));
    assert((etl::stoull(T { "5" }) == 5ULL));
    assert((etl::stoull(T { "6" }) == 6ULL));
    assert((etl::stoull(T { "7" }) == 7ULL));
    assert((etl::stoull(T { "8" }) == 8ULL));
    assert((etl::stoull(T { "9" }) == 9ULL));
    assert((etl::stoull(T { "10" }) == 10ULL));
    assert((etl::stoull(T { "11" }) == 11ULL));
    assert((etl::stoull(T { "99" }) == 99ULL));
    assert((etl::stoull(T { "11123" }) == 11123ULL));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::static_string<16>>());
    assert(test<etl::static_string<17>>());
    assert(test<etl::static_string<18>>());
    assert(test<etl::static_string<24>>());
    assert(test<etl::static_string<32>>());
    assert(test<etl::static_string<64>>());
    assert(test<etl::static_string<128>>());
    assert(test<etl::static_string<256>>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}