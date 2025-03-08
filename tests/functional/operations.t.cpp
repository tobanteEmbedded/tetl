// SPDX-License-Identifier: BSL-1.0

#include <etl/functional.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{

    CHECK(etl::detail::is_transparent<etl::plus<>>::value);
    CHECK(etl::plus<T>{}(T{2}, T{1}) == T{3});
    CHECK(etl::plus<T>{}(T{1}, T{1}) == T{2});
    CHECK(etl::plus{}(T{2}, T{1}) == T{3});
    CHECK(etl::plus{}(T{1}, T{1}) == T{2});

    CHECK(etl::detail::is_transparent<etl::minus<>>::value);
    CHECK(etl::minus<T>{}(T{99}, 98) == T{1});
    CHECK(etl::minus{}(T{2}, T{1}) == T{1});
    CHECK(etl::minus{}(T{1}, T{1}) == T{0});
    CHECK(etl::minus{}(T{99}, T{100}) == T{-1});
    CHECK(etl::minus<T>{}(T{99}, T{98}) == T{1});

    CHECK(etl::detail::is_transparent<etl::multiplies<>>::value);
    CHECK(etl::multiplies<T>{}(T{45}, 2) == T{90});
    CHECK(etl::multiplies{}(T{2}, T{1}) == T{2});
    CHECK(etl::multiplies{}(T{1}, T{1}) == T{1});
    CHECK(etl::multiplies{}(T{11}, T{10}) == T{110});
    CHECK(etl::multiplies<T>{}(T{99}, T{1}) == T{99});

    CHECK(etl::detail::is_transparent<etl::divides<>>::value);
    CHECK(etl::divides<T>{}(T{100}, 2) == T{50});
    CHECK(etl::divides{}(T{2}, T{1}) == T{2});
    CHECK(etl::divides{}(T{1}, T{1}) == T{1});
    CHECK(etl::divides{}(T{100}, T{100}) == T{1});
    CHECK(etl::divides<T>{}(T{99}, T{1}) == T{99});

    if constexpr (etl::is_integral_v<T>) {
        CHECK(etl::detail::is_transparent<etl::modulus<>>::value);
        CHECK(etl::modulus<T>{}(T{100}, 2) == T{0});
        CHECK(etl::modulus{}(T{2}, T{1}) == T{0});
        CHECK(etl::modulus{}(T{5}, T{3}) == T{2});
        CHECK(etl::modulus{}(T{100}, T{99}) == T{1});
        CHECK(etl::modulus<T>{}(T{99}, T{90}) == T{9});
    }

    CHECK(etl::detail::is_transparent<etl::negate<>>::value);
    CHECK(etl::negate<T>{}(T{50}) == T{-50});
    CHECK(etl::negate{}(T{2}) == T{-2});
    CHECK(etl::negate{}(T{-1}) == T{1});
    CHECK(etl::negate{}(T{100}) == T{-100});
    CHECK(etl::negate<T>{}(T{99}) == T{-99});

    CHECK(etl::detail::is_transparent<etl::equal_to<>>::value);
    CHECK(etl::equal_to<T>{}(T{99}, 99));
    CHECK(etl::equal_to{}(T{1}, T{1}));
    CHECK_FALSE(etl::equal_to{}(T{2}, T{1}));
    CHECK_FALSE(etl::equal_to{}(T{99}, T{100}));
    CHECK_FALSE(etl::equal_to<T>{}(T{99}, T{98}));

    CHECK(etl::detail::is_transparent<etl::not_equal_to<>>::value);
    CHECK_FALSE(etl::not_equal_to<T>{}(T{99}, 99));
    CHECK_FALSE(etl::not_equal_to{}(T{1}, T{1}));
    CHECK(etl::not_equal_to{}(T{2}, T{1}));
    CHECK(etl::not_equal_to{}(T{99}, T{100}));
    CHECK(etl::not_equal_to<T>{}(T{99}, T{98}));

    CHECK(etl::detail::is_transparent<etl::greater<>>::value);
    CHECK_FALSE(etl::greater<T>{}(T{99}, 99));
    CHECK_FALSE(etl::greater{}(T{1}, T{1}));
    CHECK(etl::greater{}(T{2}, T{1}));
    CHECK(etl::greater{}(T{101}, T{100}));
    CHECK(etl::greater<T>{}(T{99}, T{98}));

    CHECK(etl::detail::is_transparent<etl::greater_equal<>>::value);
    CHECK_FALSE(etl::greater_equal<T>{}(T{99}, 100));
    CHECK_FALSE(etl::greater_equal{}(T{1}, T{2}));
    CHECK(etl::greater_equal{}(T{2}, T{1}));
    CHECK(etl::greater_equal{}(T{100}, T{100}));
    CHECK(etl::greater_equal<T>{}(T{99}, T{98}));

    CHECK(etl::detail::is_transparent<etl::less<>>::value);
    CHECK(etl::less<T>{}(T{99}, 100));
    CHECK(etl::less{}(T{1}, T{2}));
    CHECK_FALSE(etl::less{}(T{2}, T{1}));
    CHECK_FALSE(etl::less{}(T{101}, T{100}));
    CHECK_FALSE(etl::less<T>{}(T{99}, T{98}));

    CHECK(etl::detail::is_transparent<etl::less_equal<>>::value);
    CHECK(etl::less_equal<T>{}(T{100}, 100));
    CHECK(etl::less_equal{}(T{1}, T{2}));
    CHECK_FALSE(etl::less_equal{}(T{2}, T{1}));
    CHECK_FALSE(etl::less_equal{}(T{101}, T{100}));
    CHECK_FALSE(etl::less_equal<T>{}(T{99}, T{98}));

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());

    CHECK(etl::detail::is_transparent<etl::logical_and<>>::value);
    CHECK_FALSE(etl::logical_and<bool>{}(true, false));
    CHECK(etl::logical_and<bool>{}(true, true));
    CHECK(etl::logical_and{}(true, true));

    CHECK(etl::detail::is_transparent<etl::logical_or<>>::value);
    CHECK_FALSE(etl::logical_or<bool>{}(false, false));
    CHECK(etl::logical_or<bool>{}(false, true));
    CHECK(etl::logical_or{}(true, false));

    CHECK(etl::detail::is_transparent<etl::logical_not<>>::value);
    CHECK_FALSE(etl::logical_not<bool>{}(true));
    CHECK(etl::logical_not<bool>{}(false));
    CHECK(etl::logical_not{}(false));

    CHECK(etl::detail::is_transparent<etl::bit_and<>>::value);
    CHECK(etl::bit_and<etl::uint8_t>{}(0b0000'0101, 0b0000'1001) == 1);
    CHECK(etl::bit_and<etl::uint8_t>{}(1, 0) == 0);
    CHECK(etl::bit_and{}(1, 1) == 1);

    CHECK(etl::detail::is_transparent<etl::bit_or<>>::value);
    CHECK(etl::bit_or<etl::uint8_t>{}(0b0000'0101, 0b0000'1001) == 0b0000'1101);
    CHECK(etl::bit_or<etl::uint8_t>{}(1, 0) == 1);
    CHECK(etl::bit_or{}(1, 1) == 1);

    CHECK(etl::detail::is_transparent<etl::bit_xor<>>::value);
    CHECK(etl::bit_xor<etl::uint8_t>{}(0b0000'0101, 0b0000'1001) == 0b0000'1100);
    CHECK(etl::bit_xor<etl::uint8_t>{}(1, 0) == 1);
    CHECK(etl::bit_xor{}(1, 1) == 0);

    CHECK(etl::detail::is_transparent<etl::bit_not<>>::value);
    CHECK(etl::bit_not<etl::uint8_t>{}(0b0000'0101) == 0b1111'1010);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
