// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/cmath.hpp>
#include <etl/cstring.hpp>
#include <etl/iterator.hpp>
#include <etl/set.hpp>
#include <etl/string.hpp>
#include <etl/vector.hpp>

#include <set>
#include <string>

template <typename IntType>
[[nodiscard]] auto test_sort_integers(FuzzedDataProvider& p) -> int
{
    auto generator = [&p] { return p.ConsumeIntegral<IntType>(); };
    auto vec       = etl::static_vector<IntType, 128>{};
    etl::generate_n(etl::back_inserter(vec), vec.capacity(), generator);

    auto etlSet = etl::static_set<IntType, 128>{begin(vec), end(vec)};
    auto stdSet = std::set<IntType>{begin(vec), end(vec)};
    if (etlSet.size() != stdSet.size()) {
        return 1;
    }

    etl::sort(begin(vec), end(vec));
    if (not etl::is_sorted(begin(vec), end(vec))) {
        return 1;
    }

    return 0;
}

template <typename FloatType>
[[nodiscard]] auto test_sort_floats(FuzzedDataProvider& p) -> int
{
    auto generator = [&p] { return p.ConsumeFloatingPoint<FloatType>(); };
    auto vec       = etl::static_vector<FloatType, 128>{};
    etl::generate_n(etl::back_inserter(vec), vec.capacity(), generator);

    auto etlSet = etl::static_set<FloatType, 128>{begin(vec), end(vec)};
    auto stdSet = std::set<FloatType>{begin(vec), end(vec)};
    if (etlSet.size() != stdSet.size()) {
        return 1;
    }

    etl::sort(begin(vec), end(vec));
    if (not etl::is_sorted(begin(vec), end(vec))) {
        return 1;
    }

    return 0;
}

template <typename IntType>
[[nodiscard]] auto test_search_integers(FuzzedDataProvider& p) -> int
{
    auto generator = [&p] { return p.ConsumeIntegral<IntType>(); };
    auto src       = etl::static_vector<IntType, 128>{};
    etl::generate_n(etl::back_inserter(src), src.capacity(), generator);

    auto objs = etl::static_vector<IntType, 4>{};
    etl::generate_n(etl::back_inserter(objs), objs.capacity(), generator);

    auto e = etl::search(begin(src), end(src), begin(objs), end(objs));
    auto s = std::search(begin(src), end(src), begin(objs), end(objs));
    if (e != s) {
        return 1;
    }

    return 0;
}

template <typename IntType>
[[nodiscard]] auto test_mismatch_integers(FuzzedDataProvider& p) -> int
{
    auto generator = [&p] { return p.ConsumeIntegral<IntType>(); };
    auto src       = etl::static_vector<IntType, 128>{};
    etl::generate_n(etl::back_inserter(src), src.capacity(), generator);

    auto objs = etl::static_vector<IntType, 4>{};
    etl::generate_n(etl::back_inserter(objs), objs.capacity(), generator);

    auto e = etl::mismatch(begin(src), end(src), begin(objs), end(objs));
    auto s = std::mismatch(begin(src), end(src), begin(objs), end(objs));
    if ((e.first != s.first) or (e.second != s.second)) {
        return 1;
    }

    return 0;
}

template <typename IntType>
[[nodiscard]] auto test_max_element_integers(FuzzedDataProvider& p) -> int
{
    auto generator = [&p] { return p.ConsumeIntegral<IntType>(); };
    auto src       = etl::static_vector<IntType, 128>{};
    etl::generate_n(etl::back_inserter(src), src.capacity(), generator);

    auto e = etl::max_element(begin(src), end(src));
    auto s = std::max_element(begin(src), end(src));
    if (e != s) {
        return 1;
    }

    return 0;
}

template <typename IntType>
[[nodiscard]] auto test_equal_integers(FuzzedDataProvider& p) -> int
{
    auto generator = [&p] { return p.ConsumeIntegral<IntType>(); };
    auto lhs       = etl::static_vector<IntType, 16>{};
    etl::generate_n(etl::back_inserter(lhs), lhs.capacity(), generator);

    auto rhs = etl::static_vector<IntType, 16>{};
    etl::generate_n(etl::back_inserter(rhs), rhs.capacity(), generator);

    auto e = etl::equal(begin(lhs), end(lhs), begin(rhs), end(rhs));
    auto s = std::equal(begin(lhs), end(lhs), begin(rhs), end(rhs));
    if (e != s) {
        return 1;
    }

    return 0;
}

[[nodiscard]] auto test_string(FuzzedDataProvider& p) -> int
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

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    if (size == 0) {
        return 0;
    }
    auto p = FuzzedDataProvider{data, size};

    RUN(test_sort_integers<etl::uint8_t>(p));
    RUN(test_sort_integers<etl::uint16_t>(p));
    RUN(test_sort_integers<etl::uint32_t>(p));
    RUN(test_sort_integers<etl::uint64_t>(p));

    RUN(test_sort_integers<etl::uint8_t>(p));
    RUN(test_sort_integers<etl::uint16_t>(p));
    RUN(test_sort_integers<etl::uint32_t>(p));
    RUN(test_sort_integers<etl::uint64_t>(p));

    RUN(test_sort_floats<etl::float_t>(p));
    RUN(test_sort_floats<etl::double_t>(p));
    RUN(test_sort_floats<long double>(p));

    RUN(test_search_integers<etl::uint8_t>(p));
    RUN(test_search_integers<etl::uint16_t>(p));
    RUN(test_search_integers<etl::uint32_t>(p));
    RUN(test_search_integers<etl::uint64_t>(p));

    RUN(test_search_integers<etl::uint8_t>(p));
    RUN(test_search_integers<etl::uint16_t>(p));
    RUN(test_search_integers<etl::uint32_t>(p));
    RUN(test_search_integers<etl::uint64_t>(p));

    RUN(test_mismatch_integers<etl::uint8_t>(p));
    RUN(test_mismatch_integers<etl::uint16_t>(p));
    RUN(test_mismatch_integers<etl::uint32_t>(p));
    RUN(test_mismatch_integers<etl::uint64_t>(p));

    RUN(test_mismatch_integers<etl::uint8_t>(p));
    RUN(test_mismatch_integers<etl::uint16_t>(p));
    RUN(test_mismatch_integers<etl::uint32_t>(p));
    RUN(test_mismatch_integers<etl::uint64_t>(p));

    RUN(test_max_element_integers<etl::uint8_t>(p));
    RUN(test_max_element_integers<etl::uint16_t>(p));
    RUN(test_max_element_integers<etl::uint32_t>(p));
    RUN(test_max_element_integers<etl::uint64_t>(p));

    RUN(test_max_element_integers<etl::uint8_t>(p));
    RUN(test_max_element_integers<etl::uint16_t>(p));
    RUN(test_max_element_integers<etl::uint32_t>(p));
    RUN(test_max_element_integers<etl::uint64_t>(p));

    RUN(test_equal_integers<etl::uint8_t>(p));
    RUN(test_equal_integers<etl::uint16_t>(p));
    RUN(test_equal_integers<etl::uint32_t>(p));
    RUN(test_equal_integers<etl::uint64_t>(p));

    RUN(test_equal_integers<etl::uint8_t>(p));
    RUN(test_equal_integers<etl::uint16_t>(p));
    RUN(test_equal_integers<etl::uint32_t>(p));
    RUN(test_equal_integers<etl::uint64_t>(p));

    RUN(test_string(p));

    return 0;
}
