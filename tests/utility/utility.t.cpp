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
        auto original = T{42};
        auto const b  = etl::exchange(original, T{43});
        CHECK(original == T{43});
        CHECK(b == T{42});

        auto const c = etl::exchange(original, T{44});
        CHECK(original == T{44});
        CHECK(c == T{43});
    }

    // as_const
    {
        auto original = T{42};
        CHECK(!(etl::is_const_v<decltype(original)>));

        auto const& ref = etl::as_const(original);
        CHECK(etl::is_const_v<etl::remove_reference_t<decltype(ref)>>);

        CHECK(original == 42);
        CHECK(original == ref);
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

        CHECK(is_same_v<decltype(to_underlying(c_enum::foo)), T>);
        CHECK(is_same_v<decltype(to_underlying(s_enum::foo)), T>);

        CHECK(to_underlying(c_enum::foo) == T{0});
        CHECK(to_underlying(c_enum::bar) == T{1});
        CHECK(to_underlying(c_enum::baz) == T{42});

        CHECK(to_underlying(s_enum::foo) == T{0});
        CHECK(to_underlying(s_enum::bar) == T{1});
        CHECK(to_underlying(s_enum::baz) == T{42});
    }

    {
        CHECK(etl::in_range<T>(0));
        CHECK(etl::in_range<T>(etl::numeric_limits<T>::min()));
        CHECK(etl::in_range<T>(etl::numeric_limits<T>::max()));
    }
    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int64_t>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
