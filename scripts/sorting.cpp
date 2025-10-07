// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

// Count compare, copy, move & swap operations in sort algorithms.
// Run from root of git repo:
// clang++ -std=c++23 -O3 -march=native -I include scripts/sorting.cpp -o sorting
// ./sorting

#include <etl/algorithm.hpp>
#include <etl/functional.hpp>
#include <etl/iterator.hpp>
#include <etl/numeric.hpp>
#include <etl/span.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <print>
#include <random>
#include <utility>
#include <vector>

struct SortCounters {
    inline static uint64_t comps  = 0;
    inline static uint64_t swaps  = 0; // times your swap(T&,T&) was used
    inline static uint64_t copies = 0; // copy-ctor or copy-assign
    inline static uint64_t moves  = 0; // move-ctor or move-assign

    static void reset()
    {
        comps = swaps = copies = moves = 0;
    }
};

template <typename T>
struct Instrumented {
    T v;

    Instrumented() = default;
    Instrumented(T const& x)
        : v(x)
    {
    }
    Instrumented(T&& x) noexcept(etl::is_nothrow_move_constructible_v<T>)
        : v(etl::move(x))
    {
    }

    Instrumented(Instrumented const& o)
        : v(o.v)
    {
        ++SortCounters::copies;
    }
    Instrumented(Instrumented&& o) noexcept(etl::is_nothrow_move_constructible_v<T>)
        : v(etl::move(o.v))
    {
        ++SortCounters::moves;
    }

    auto operator=(Instrumented const& o) -> Instrumented&
    {
        v = o.v;
        ++SortCounters::copies;
        return *this;
    }
    auto operator=(Instrumented&& o) noexcept(etl::is_nothrow_move_assignable_v<T>) -> Instrumented&
    {
        v = etl::move(o.v);
        ++SortCounters::moves;
        return *this;
    }

    friend auto operator<(Instrumented const& lhs, Instrumented const& rhs) -> bool
    {
        ++SortCounters::comps;
        return lhs.v < rhs.v;
    }

    friend auto swap(Instrumented& lhs, Instrumented& rhs) noexcept(noexcept(etl::swap(lhs.v, rhs.v))) -> void
    {
        using etl::swap;
        swap(lhs.v, rhs.v);
        ++SortCounters::swaps;
    }
};

// handy lower bound log2(n!) to compare with comparison sorts’ theoretical minimum
inline double log2_factorial(size_t n)
{
    double s = 0.0;
    for (size_t i = 2; i <= n; ++i) {
        s += std::log2((double)i);
    }
    return s;
}

template <typename SortFn>
void run_case(char const* label, SortFn sorter, size_t n)
{
    std::vector<Instrumented<int>> a;
    a.reserve(n);
    std::mt19937 rng(123456789);
    for (size_t i = 0; i < n; ++i) {
        a.emplace_back(int(rng()));
        // a.emplace_back(int(i));
    }

    SortCounters::reset();
    auto aview = etl::span<Instrumented<int>>{a.data(), a.size()};
    sorter(aview.begin(), aview.end()); // call your sorter or std::sort

    double const lb    = log2_factorial(n);        // ~ n log2 n - 1.44 n
    double const nlogn = n * std::log2((double)n); // rough model

    std::println(
        "{:20}|{:^10}|{:^15}|{:^15.3f}|{:^15.3f}|{:^15.3f}|{:^10}|{:^10}|{:^10}",
        label,
        n,
        SortCounters::comps,
        SortCounters::comps / static_cast<double>(n * n),
        SortCounters::comps / std::max(1.0, nlogn),
        SortCounters::comps / std::max(1.0, lb),
        SortCounters::swaps,
        SortCounters::copies,
        SortCounters::moves
    );
}

int main()
{
    for (size_t n : {1u << 2, 1u << 4, 1u << 8, 1u << 12, 1u << 14}) {
        std::println(
            "{:^20}|{:^10}|{:^15}|{:^15}|{:^15}|{:^15}|{:^10}|{:^10}|{:^10}",
            "Algorithm",
            "Size",
            "Comps",
            "Comps/(n^2)",
            "Comps/(nlogn)",
            "Comps/(n!)",
            "Swap",
            "Copy",
            "Move"
        );

        run_case("std::sort", [](auto f, auto l) { std::sort(f, l); }, n);
        run_case("etl::sort", [](auto f, auto l) { etl::sort(f, l); }, n);

        run_case("std::stable_sort", [](auto f, auto l) { std::stable_sort(f, l); }, n);
        run_case("etl::stable_sort", [](auto f, auto l) { etl::stable_sort(f, l); }, n);

        run_case("etl::merge_sort", [](auto f, auto l) { etl::merge_sort(f, l); }, n);
        run_case("etl::quick_sort", [](auto f, auto l) { etl::quick_sort(f, l); }, n);
        run_case("etl::insertion_sort", [](auto f, auto l) { etl::insertion_sort(f, l); }, n);
        run_case("etl::bubble_sort", [](auto f, auto l) { etl::bubble_sort(f, l); }, n);
        run_case("etl::exchange_sort", [](auto f, auto l) { etl::exchange_sort(f, l); }, n);
        run_case("etl::gnome_sort", [](auto f, auto l) { etl::gnome_sort(f, l); }, n);

        run_case("std::nth_element", [](auto f, auto l) { std::nth_element(f, etl::midpoint(f, l), l); }, n);
        run_case("etl::nth_element", [](auto f, auto l) { etl::nth_element(f, etl::midpoint(f, l), l); }, n);
        std::puts("");
    }
}
