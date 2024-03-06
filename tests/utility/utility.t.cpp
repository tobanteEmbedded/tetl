// SPDX-License-Identifier: BSL-1.0

#include <etl/utility.hpp>

#include <etl/cstdint.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using etl::is_same_v;

    // exchange
    {
        auto original = T {42};
        auto const b  = etl::exchange(original, T {43});
        assert(original == T {43});
        assert(b == T {42});

        auto const c = etl::exchange(original, T {44});
        assert(original == T {44});
        assert(c == T {43});
    }

    // as_const
    {
        auto original = T {42};
        assert(!(etl::is_const_v<decltype(original)>));

        auto const& ref = etl::as_const(original);
        assert((etl::is_const_v<etl::remove_reference_t<decltype(ref)>>));

        assert((original == 42));
        assert((original == ref));
    }

    // to_underlying
    {
        using etl::is_same_v;
        using etl::to_underlying;

        enum c_enum : T {
            foo = 0,
            bar = 1,
            baz = 42,
        };

        enum struct s_enum : T {
            foo = 0,
            bar = 1,
            baz = 42,
        };

        assert((is_same_v<decltype(to_underlying(c_enum::foo)), T>));
        assert((is_same_v<decltype(to_underlying(s_enum::foo)), T>));

        assert((to_underlying(c_enum::foo) == T {0}));
        assert((to_underlying(c_enum::bar) == T {1}));
        assert((to_underlying(c_enum::baz) == T {42}));

        assert((to_underlying(s_enum::foo) == T {0}));
        assert((to_underlying(s_enum::bar) == T {1}));
        assert((to_underlying(s_enum::baz) == T {42}));
    }

    {
        assert((etl::in_range<T>(0)));
        assert((etl::in_range<T>(etl::numeric_limits<T>::min())));
        assert((etl::in_range<T>(etl::numeric_limits<T>::max())));
    }
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
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
