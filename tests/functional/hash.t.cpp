/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/functional.hpp"

#include "etl/algorithm.hpp"
#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::hash<etl::nullptr_t> {}(nullptr) == 0);

    assert(etl::hash<bool> {}(true) != 0);
    assert(etl::hash<char16_t> {}('a') != 0);
    assert(etl::hash<char32_t> {}('a') != 0);
    assert(etl::hash<wchar_t> {}('a') != 0);

    assert(etl::hash<T> {}(42) != 0);
    assert(etl::hash<T> {}(42) == etl::hash<T> {}(42));

#if __has_builtin(__builtin_is_constant_evaluated)
    if (!etl::is_constant_evaluated()) {
        auto val = T { 42 };
        assert(etl::hash<T*> {}(&val) != 0);
    }
#endif

#if defined(__cpp_char8_t)
    assert(etl::hash<char8_t> {}('a') != 0);
#endif

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<char>());
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<etl::uint8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
    assert(test<float>());
    assert(test<double>());
    assert(test<long double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
