/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#undef NDEBUG

#include <stdio.h> // for printf, size_t

#include "etl/map.hpp"     // for map
#include "etl/warning.hpp" // for ignore_unused

auto basic_usage() -> void
{
    // Create map with no elements and a capacity of 16 key-value pairs.
    auto map = etl::map<int, float, 16> {};
    printf("size: %d", static_cast<int>(map.size()));
}

// Custom key type.
struct Key {
    constexpr explicit Key(size_t val) : val_ { val } { }

    [[nodiscard]] constexpr auto key() const -> size_t { return val_; }

private:
    size_t val_;
};

auto custom_compare() -> void
{
    // Lambda for comparing to objects of type Key.
    constexpr auto compare
        = [](Key& lhs, Key& rhs) { return lhs.key() < rhs.key(); };

    // Create map of with <Key,int> pair with the comparator compare, no
    // elements and a capacity of 16.
    auto data = etl::map<Key, int, 16, decltype(compare)> {};
    etl::ignore_unused(data);
}

auto main() -> int
{
    basic_usage();
    custom_compare();
    return 0;
}