/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/functional.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("functional: plus", "[functional]", int, float, double)
{
    using T = TestType;

    STATIC_REQUIRE(etl::detail::is_transparent<etl::plus<>>::value);
    CHECK(etl::plus<T> {}(T { 2 }, T { 1 }) == T { 3 });
    CHECK(etl::plus<T> {}(T { 1 }, T { 1 }) == T { 2 });
    CHECK(etl::plus<T> {}(T { 100 }, T { 100 }) == T { 200 });

    CHECK(etl::plus<> {}(T { 2 }, T { 1 }) == T { 3 });
    CHECK(etl::plus<> {}(T { 1 }, T { 1 }) == T { 2 });
    CHECK(etl::plus<> {}(T { 100 }, T { 100 }) == T { 200 });
}

TEMPLATE_TEST_CASE("functional: minus", "[functional]", int, float, double)
{
    using T = TestType;

    STATIC_REQUIRE(etl::detail::is_transparent<etl::minus<>>::value);
    CHECK(etl::minus<T> {}(T { 99 }, 98) == T { 1 });
    CHECK(etl::minus<> {}(T { 2 }, T { 1 }) == T { 1 });
    CHECK(etl::minus<> {}(T { 1 }, T { 1 }) == T { 0 });
    CHECK(etl::minus<> {}(T { 99 }, T { 100 }) == T { -1 });
    CHECK(etl::minus<T> {}(T { 99 }, T { 98 }) == T { 1 });
}

TEMPLATE_TEST_CASE("functional: multiplies", "[functional]", int, float, double)
{
    using T = TestType;

    STATIC_REQUIRE(etl::detail::is_transparent<etl::multiplies<>>::value);

    CHECK(etl::multiplies<T> {}(T { 99 }, 2) == T { 198 });
    CHECK(etl::multiplies<> {}(T { 2 }, T { 1 }) == T { 2 });
    CHECK(etl::multiplies<> {}(T { 1 }, T { 1 }) == T { 1 });
    CHECK(etl::multiplies<> {}(T { 99 }, T { 100 }) == T { 9900 });

    CHECK(etl::multiplies<T> {}(T { 99 }, T { 1 }) == T { 99 });
}

TEMPLATE_TEST_CASE("functional: divides", "[functional]", int, float, double)
{
    using T = TestType;

    STATIC_REQUIRE(etl::detail::is_transparent<etl::divides<>>::value);

    CHECK(etl::divides<T> {}(T { 100 }, 2) == T { 50 });
    CHECK(etl::divides<> {}(T { 2 }, T { 1 }) == T { 2 });
    CHECK(etl::divides<> {}(T { 1 }, T { 1 }) == T { 1 });
    CHECK(etl::divides<> {}(T { 100 }, T { 100 }) == T { 1 });

    CHECK(etl::divides<T> {}(T { 99 }, T { 1 }) == T { 99 });
}

TEMPLATE_TEST_CASE("functional: modulus", "[functional]", int, unsigned)
{
    using T = TestType;

    STATIC_REQUIRE(etl::detail::is_transparent<etl::modulus<>>::value);

    CHECK(etl::modulus<T> {}(T { 100 }, 2) == T { 0 });
    CHECK(etl::modulus<> {}(T { 2 }, T { 1 }) == T { 0 });
    CHECK(etl::modulus<> {}(T { 5 }, T { 3 }) == T { 2 });
    CHECK(etl::modulus<> {}(T { 100 }, T { 99 }) == T { 1 });

    CHECK(etl::modulus<T> {}(T { 99 }, T { 90 }) == T { 9 });
}

TEMPLATE_TEST_CASE("functional: negate", "[functional]", int, float, double)
{
    using T = TestType;

    STATIC_REQUIRE(etl::detail::is_transparent<etl::negate<>>::value);

    CHECK(etl::negate<T> {}(T { 50 }) == T { -50 });
    CHECK(etl::negate<> {}(T { 2 }) == T { -2 });
    CHECK(etl::negate<> {}(T { -1 }) == T { 1 });
    CHECK(etl::negate<> {}(T { 100 }) == T { -100 });

    CHECK(etl::negate<T> {}(T { 99 }) == T { -99 });
}

TEMPLATE_TEST_CASE("functional: equal_to", "[functional]", int, float, double)
{
    using T = TestType;

    REQUIRE(etl::equal_to<T> {}(T { 99 }, 99));
    REQUIRE(etl::equal_to<> {}(T { 1 }, T { 1 }));

    REQUIRE_FALSE(etl::equal_to<> {}(T { 2 }, T { 1 }));
    REQUIRE_FALSE(etl::equal_to<> {}(T { 99 }, T { 100 }));
    REQUIRE_FALSE(etl::equal_to<T> {}(T { 99 }, T { 98 }));
}

TEMPLATE_TEST_CASE(
    "functional: not_equal_to", "[functional]", int, float, double)
{
    using T = TestType;

    REQUIRE_FALSE(etl::not_equal_to<T> {}(T { 99 }, 99));
    REQUIRE_FALSE(etl::not_equal_to<> {}(T { 1 }, T { 1 }));

    REQUIRE(etl::not_equal_to<> {}(T { 2 }, T { 1 }));
    REQUIRE(etl::not_equal_to<> {}(T { 99 }, T { 100 }));
    REQUIRE(etl::not_equal_to<T> {}(T { 99 }, T { 98 }));
}

TEMPLATE_TEST_CASE("functional: greater", "[functional]", int, float, double)
{
    using T = TestType;

    REQUIRE_FALSE(etl::greater<T> {}(T { 99 }, 99));
    REQUIRE_FALSE(etl::greater<> {}(T { 1 }, T { 1 }));

    REQUIRE(etl::greater<> {}(T { 2 }, T { 1 }));
    REQUIRE(etl::greater<> {}(T { 101 }, T { 100 }));
    REQUIRE(etl::greater<T> {}(T { 99 }, T { 98 }));
}

TEMPLATE_TEST_CASE(
    "functional: greater_equal", "[functional]", int, float, double)
{
    using T = TestType;

    REQUIRE_FALSE(etl::greater_equal<T> {}(T { 99 }, 100));
    REQUIRE_FALSE(etl::greater_equal<> {}(T { 1 }, T { 2 }));

    REQUIRE(etl::greater_equal<> {}(T { 2 }, T { 1 }));
    REQUIRE(etl::greater_equal<> {}(T { 100 }, T { 100 }));
    REQUIRE(etl::greater_equal<T> {}(T { 99 }, T { 98 }));
}

TEMPLATE_TEST_CASE("functional: less", "[functional]", int, float, double)
{
    using T = TestType;

    REQUIRE(etl::less<T> {}(T { 99 }, 100));
    REQUIRE(etl::less<> {}(T { 1 }, T { 2 }));

    REQUIRE_FALSE(etl::less<> {}(T { 2 }, T { 1 }));
    REQUIRE_FALSE(etl::less<> {}(T { 101 }, T { 100 }));
    REQUIRE_FALSE(etl::less<T> {}(T { 99 }, T { 98 }));
}

TEMPLATE_TEST_CASE("functional: less_equal", "[functional]", int, float, double)
{
    using T = TestType;

    REQUIRE(etl::less_equal<T> {}(T { 100 }, 100));
    REQUIRE(etl::less_equal<> {}(T { 1 }, T { 2 }));

    REQUIRE_FALSE(etl::less_equal<> {}(T { 2 }, T { 1 }));
    REQUIRE_FALSE(etl::less_equal<> {}(T { 1024 }, T { 100 }));
    REQUIRE_FALSE(etl::less_equal<T> {}(T { 99 }, T { 98 }));
}

TEST_CASE("functional: logical_and", "[functional]")
{
    REQUIRE_FALSE(etl::logical_and<bool> {}(true, false));
    REQUIRE(etl::logical_and<bool> {}(true, true));
    REQUIRE(etl::logical_and<> {}(true, true));
}

TEST_CASE("functional: logical_or", "[functional]")
{
    REQUIRE_FALSE(etl::logical_or<bool> {}(false, false));
    REQUIRE(etl::logical_or<bool> {}(false, true));
    REQUIRE(etl::logical_or<> {}(true, false));
}

TEST_CASE("functional: logical_not", "[functional]")
{
    REQUIRE_FALSE(etl::logical_not<bool> {}(true));
    REQUIRE(etl::logical_not<bool> {}(false));
    REQUIRE(etl::logical_not<> {}(false));
}

TEST_CASE("functional: bit_and", "[functional]")
{
    REQUIRE(etl::bit_and<etl::uint8_t> {}(0b0000'0101, 0b0000'1001) == 1);
    REQUIRE(etl::bit_and<etl::uint8_t> {}(1, 0) == 0);
    REQUIRE(etl::bit_and<> {}(1, 1) == 1);
}

TEST_CASE("functional: bit_or", "[functional]")
{
    REQUIRE(
        etl::bit_or<etl::uint8_t> {}(0b0000'0101, 0b0000'1001) == 0b0000'1101);
    REQUIRE(etl::bit_or<etl::uint8_t> {}(1, 0) == 1);
    REQUIRE(etl::bit_or<> {}(1, 1) == 1);
}

TEST_CASE("functional: bit_xor", "[functional]")
{
    REQUIRE(
        etl::bit_xor<etl::uint8_t> {}(0b0000'0101, 0b0000'1001) == 0b0000'1100);
    REQUIRE(etl::bit_xor<etl::uint8_t> {}(1, 0) == 1);
    REQUIRE(etl::bit_xor<> {}(1, 1) == 0);
}

TEST_CASE("functional: bit_not", "[functional]")
{
    REQUIRE(etl::bit_not<etl::uint8_t> {}(0b0000'0101) == 0b1111'1010);
}

TEST_CASE("functional: hash", "[functional]")
{
    CHECK(etl::hash<bool> {}(true) != 0);

    CHECK(etl::hash<char16_t> {}('a') != 0);
    CHECK(etl::hash<char32_t> {}('a') != 0);
    CHECK(etl::hash<wchar_t> {}('a') != 0);

    CHECK(etl::hash<signed char> {}(42) != 0);
    CHECK(etl::hash<unsigned char> {}(143) != 0);
    CHECK(etl::hash<short> {}(143) != 0);
    CHECK(etl::hash<unsigned short> {}(143) != 0);
    CHECK(etl::hash<int> {}(143) != 0);
    CHECK(etl::hash<unsigned int> {}(143) != 0);
    CHECK(etl::hash<long> {}(143) != 0);
    CHECK(etl::hash<unsigned long> {}(143) != 0);
    CHECK(etl::hash<long long> {}(143) != 0);
    CHECK(etl::hash<unsigned long long> {}(143) != 0);

    CHECK(etl::hash<float> {}(143) != 0);
    CHECK(etl::hash<double> {}(143) != 0);
    CHECK(etl::hash<long double> {}(143) != 0);

    etl::array<float, 4> data {};
    CHECK(etl::hash<decltype(data)*> {}(&data) != 0);

    CHECK(etl::hash<etl::nullptr_t> {}(nullptr) == 0);
}

TEST_CASE("functional: invoke", "[functional]")
{
    auto lambda = [](int x) -> int { return x; };
    REQUIRE(etl::invoke(lambda, 1) == 1);
    REQUIRE(etl::invoke([]() { return 42; }) == 42);
}

TEMPLATE_TEST_CASE(
    "functional: inplace_function", "[functional]", int, float, double)
{
    using T = TestType;
    using etl::inplace_function;

    auto func = inplace_function<T(T)> {
        [](T x) { return x + T(1); },
    };

    REQUIRE(func(T { 41 }) == T { 42 });
    REQUIRE(etl::invoke(func, T { 41 }) == T { 42 });
    REQUIRE(static_cast<bool>(func));
    REQUIRE_FALSE(static_cast<bool>(inplace_function<T(T)> {}));
    REQUIRE_FALSE(static_cast<bool>(inplace_function<T(T)> { nullptr }));
}

namespace {

template <typename T>
auto test_function_ref(T x) -> T
{
    return x * 2;
}

} // namespace
TEMPLATE_TEST_CASE(
    "functional: function_ref", "[functional]", int, float, double)
{
    using T      = TestType;
    auto lambda  = [](T x) { return x + T(1); };
    auto lambda2 = [](T x) { return x + T(0); };

    STATIC_REQUIRE(sizeof(etl::function_ref<T(T)>) == sizeof(void*) * 2);

    auto ref = etl::function_ref<T(T)> { lambda };
    REQUIRE(ref(T { 41 }) == T { 42 });
    REQUIRE(etl::invoke(ref, T { 41 }) == T { 42 });

    ref = test_function_ref<T>;
    REQUIRE(ref(T { 41 }) == T { 82 });
    REQUIRE(etl::invoke(ref, T { 41 }) == T { 82 });

    ref = lambda2;
    REQUIRE(ref(T { 41 }) == T { 41 });
    REQUIRE(etl::invoke(ref, T { 41 }) == T { 41 });

    auto other = etl::function_ref<T(T)> { test_function_ref<T> };
    REQUIRE(other(T { 41 }) == T { 82 });
    REQUIRE(etl::invoke(other, T { 41 }) == T { 82 });

    other.swap(ref);
    REQUIRE(ref(T { 41 }) == T { 82 });
    REQUIRE(etl::invoke(ref, T { 41 }) == T { 82 });
    REQUIRE(other(T { 41 }) == T { 41 });
    REQUIRE(etl::invoke(other, T { 41 }) == T { 41 });

    swap(other, ref);
    REQUIRE(other(T { 41 }) == T { 82 });
    REQUIRE(etl::invoke(other, T { 41 }) == T { 82 });
    REQUIRE(ref(T { 41 }) == T { 41 });
    REQUIRE(etl::invoke(ref, T { 41 }) == T { 41 });
}