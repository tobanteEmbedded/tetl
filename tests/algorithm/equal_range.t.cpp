// SPDX-License-Identifier: BSL-1.0

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/functional.hpp"

#include "testing/iterator_types.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // cppreference.com example

    struct S {
        constexpr S(T n, char na) : number {n}, name {na} { }

        constexpr auto operator<(S const& s) const -> bool { return number < s.number; }

        T number;
        char name;
    };

    // note: not ordered, only partitioned w.r.t. S defined below
    auto vec = etl::array<S, 6> {
        S {T(1), 'A'},
        S {T(2), 'B'},
        S {T(2), 'C'},
        S {T(2), 'D'},
        S {T(4), 'G'},
        S {T(3), 'F'},
    };

    auto const value = S {T(2), '?'};
    auto const p     = etl::equal_range(vec.begin(), vec.end(), value);
    assert(p.first->name == 'B');

    // clang-format off
    assert(etl::equal_range(FwdIter(begin(vec)), FwdIter(end(vec)), value).first->name == 'B');
    // clang-format on

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
