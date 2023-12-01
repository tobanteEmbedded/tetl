// SPDX-License-Identifier: BSL-1.0

#include "etl/functional.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{

    assert(etl::detail::is_transparent<etl::plus<>>::value);
    assert((etl::plus<T> {}(T {2}, T {1}) == T {3}));
    assert((etl::plus<T> {}(T {1}, T {1}) == T {2}));
    assert((etl::plus<> {}(T {2}, T {1}) == T {3}));
    assert((etl::plus<> {}(T {1}, T {1}) == T {2}));

    assert(etl::detail::is_transparent<etl::minus<>>::value);
    assert((etl::minus<T> {}(T {99}, 98) == T {1}));
    assert((etl::minus<> {}(T {2}, T {1}) == T {1}));
    assert((etl::minus<> {}(T {1}, T {1}) == T {0}));
    assert((etl::minus<> {}(T {99}, T {100}) == T {-1}));
    assert((etl::minus<T> {}(T {99}, T {98}) == T {1}));

    assert(etl::detail::is_transparent<etl::multiplies<>>::value);
    assert((etl::multiplies<T> {}(T {45}, 2) == T {90}));
    assert((etl::multiplies<> {}(T {2}, T {1}) == T {2}));
    assert((etl::multiplies<> {}(T {1}, T {1}) == T {1}));
    assert((etl::multiplies<> {}(T {11}, T {10}) == T {110}));
    assert((etl::multiplies<T> {}(T {99}, T {1}) == T {99}));

    assert(etl::detail::is_transparent<etl::divides<>>::value);
    assert((etl::divides<T> {}(T {100}, 2) == T {50}));
    assert((etl::divides<> {}(T {2}, T {1}) == T {2}));
    assert((etl::divides<> {}(T {1}, T {1}) == T {1}));
    assert((etl::divides<> {}(T {100}, T {100}) == T {1}));
    assert((etl::divides<T> {}(T {99}, T {1}) == T {99}));

    if constexpr (etl::is_integral_v<T>) {
        assert(etl::detail::is_transparent<etl::modulus<>>::value);
        assert((etl::modulus<T> {}(T {100}, 2) == T {0}));
        assert((etl::modulus<> {}(T {2}, T {1}) == T {0}));
        assert((etl::modulus<> {}(T {5}, T {3}) == T {2}));
        assert((etl::modulus<> {}(T {100}, T {99}) == T {1}));
        assert((etl::modulus<T> {}(T {99}, T {90}) == T {9}));
    }

    assert(etl::detail::is_transparent<etl::negate<>>::value);
    assert((etl::negate<T> {}(T {50}) == T {-50}));
    assert((etl::negate<> {}(T {2}) == T {-2}));
    assert((etl::negate<> {}(T {-1}) == T {1}));
    assert((etl::negate<> {}(T {100}) == T {-100}));
    assert((etl::negate<T> {}(T {99}) == T {-99}));

    assert(etl::detail::is_transparent<etl::equal_to<>>::value);
    assert((etl::equal_to<T> {}(T {99}, 99)));
    assert((etl::equal_to<> {}(T {1}, T {1})));
    assert(!(etl::equal_to<> {}(T {2}, T {1})));
    assert(!(etl::equal_to<> {}(T {99}, T {100})));
    assert(!(etl::equal_to<T> {}(T {99}, T {98})));

    assert(etl::detail::is_transparent<etl::not_equal_to<>>::value);
    assert(!(etl::not_equal_to<T> {}(T {99}, 99)));
    assert(!(etl::not_equal_to<> {}(T {1}, T {1})));
    assert((etl::not_equal_to<> {}(T {2}, T {1})));
    assert((etl::not_equal_to<> {}(T {99}, T {100})));
    assert((etl::not_equal_to<T> {}(T {99}, T {98})));

    assert(etl::detail::is_transparent<etl::greater<>>::value);
    assert(!(etl::greater<T> {}(T {99}, 99)));
    assert(!(etl::greater<> {}(T {1}, T {1})));
    assert((etl::greater<> {}(T {2}, T {1})));
    assert((etl::greater<> {}(T {101}, T {100})));
    assert((etl::greater<T> {}(T {99}, T {98})));

    assert(etl::detail::is_transparent<etl::greater_equal<>>::value);
    assert(!(etl::greater_equal<T> {}(T {99}, 100)));
    assert(!(etl::greater_equal<> {}(T {1}, T {2})));
    assert((etl::greater_equal<> {}(T {2}, T {1})));
    assert((etl::greater_equal<> {}(T {100}, T {100})));
    assert((etl::greater_equal<T> {}(T {99}, T {98})));

    assert(etl::detail::is_transparent<etl::less<>>::value);
    assert((etl::less<T> {}(T {99}, 100)));
    assert((etl::less<> {}(T {1}, T {2})));
    assert(!(etl::less<> {}(T {2}, T {1})));
    assert(!(etl::less<> {}(T {101}, T {100})));
    assert(!(etl::less<T> {}(T {99}, T {98})));

    assert(etl::detail::is_transparent<etl::less_equal<>>::value);
    assert((etl::less_equal<T> {}(T {100}, 100)));
    assert((etl::less_equal<> {}(T {1}, T {2})));
    assert(!(etl::less_equal<> {}(T {2}, T {1})));
    assert(!(etl::less_equal<> {}(T {101}, T {100})));
    assert(!(etl::less_equal<T> {}(T {99}, T {98})));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());

    assert(etl::detail::is_transparent<etl::logical_and<>>::value);
    assert(!(etl::logical_and<bool> {}(true, false)));
    assert((etl::logical_and<bool> {}(true, true)));
    assert((etl::logical_and<> {}(true, true)));

    assert(etl::detail::is_transparent<etl::logical_or<>>::value);
    assert(!(etl::logical_or<bool> {}(false, false)));
    assert((etl::logical_or<bool> {}(false, true)));
    assert((etl::logical_or<> {}(true, false)));

    assert(etl::detail::is_transparent<etl::logical_not<>>::value);
    assert(!(etl::logical_not<bool> {}(true)));
    assert((etl::logical_not<bool> {}(false)));
    assert((etl::logical_not<> {}(false)));

    using etl::uint8_t;

    assert(etl::detail::is_transparent<etl::bit_and<>>::value);
    assert((etl::bit_and<uint8_t> {}(0b0000'0101, 0b0000'1001) == 1));
    assert((etl::bit_and<uint8_t> {}(1, 0) == 0));
    assert((etl::bit_and<> {}(1, 1) == 1));

    assert(etl::detail::is_transparent<etl::bit_or<>>::value);
    assert((etl::bit_or<uint8_t> {}(0b0000'0101, 0b0000'1001) == 0b0000'1101));
    assert((etl::bit_or<uint8_t> {}(1, 0) == 1));
    assert((etl::bit_or<> {}(1, 1) == 1));

    assert(etl::detail::is_transparent<etl::bit_xor<>>::value);
    assert((etl::bit_xor<uint8_t> {}(0b0000'0101, 0b0000'1001) == 0b0000'1100));
    assert((etl::bit_xor<uint8_t> {}(1, 0) == 1));
    assert((etl::bit_xor<> {}(1, 1) == 0));

    assert(etl::detail::is_transparent<etl::bit_not<>>::value);
    assert((etl::bit_not<uint8_t> {}(0b0000'0101) == 0b1111'1010));

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
