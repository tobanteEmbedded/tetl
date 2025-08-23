// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/functional.hpp>
    #include <etl/type_traits.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK(etl::hash<etl::nullptr_t>{}(nullptr) == 0);

    CHECK(etl::hash<bool>{}(true) != 0);
    CHECK(etl::hash<char16_t>{}('a') != 0);
    CHECK(etl::hash<char32_t>{}('a') != 0);
    CHECK(etl::hash<wchar_t>{}('a') != 0);

    CHECK(etl::hash<T>{}(42) != 0);
    CHECK(etl::hash<T>{}(42) == etl::hash<T>{}(42));

#if __has_builtin(__builtin_is_constant_evaluated)
    if (!etl::is_constant_evaluated()) {
        auto val = T{42};
        CHECK(etl::hash<T*>{}(&val) != 0);
    }
#endif

    CHECK(etl::hash<char8_t>{}('a') != 0);

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<char>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
