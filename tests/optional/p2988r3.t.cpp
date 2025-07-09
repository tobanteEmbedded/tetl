// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.memory;
import etl.optional;
import etl.type_traits;
import etl.utility;
#else
    #include <etl/memory.hpp>
    #include <etl/optional.hpp>
    #include <etl/type_traits.hpp>
    #include <etl/utility.hpp>
#endif

namespace {

template <typename T>
constexpr auto test() -> bool
{
    using optional = etl::optional<T&>;
    CHECK_SAME_TYPE(typename optional::value_type, T&);
    CHECK(etl::is_trivially_copyable_v<optional>);
    CHECK(etl::is_trivially_destructible_v<optional>);

    auto empty = optional{};
    CHECK_FALSE(static_cast<bool>(empty));
    CHECK_FALSE(empty.has_value());
    CHECK(empty.operator->() == nullptr);

    auto null = optional{etl::nullopt};
    CHECK_FALSE(static_cast<bool>(null));
    CHECK_FALSE(null.has_value());
    CHECK(null.operator->() == nullptr);

    auto val = T(42);
    auto opt = optional{val};
    CHECK(static_cast<bool>(opt));
    CHECK(opt.has_value());
    CHECK(opt.operator->() == etl::addressof(val));
    CHECK(*opt == T(42));

    opt = empty;
    CHECK_FALSE(static_cast<bool>(opt));
    CHECK_FALSE(opt.has_value());

    auto one = T(1);
    opt      = one;
    CHECK(static_cast<bool>(opt));
    CHECK(opt.has_value());
    CHECK(*opt == one);

    opt = etl::nullopt;
    CHECK_FALSE(static_cast<bool>(opt));
    CHECK_FALSE(opt.has_value());

    auto two = T(2);
    opt      = two;
    CHECK(static_cast<bool>(opt));
    CHECK(opt.has_value());
    CHECK(*opt == two);

    opt.reset();
    CHECK_FALSE(static_cast<bool>(opt));
    CHECK_FALSE(opt.has_value());

    opt.emplace(two);
    CHECK(static_cast<bool>(opt));
    CHECK(opt.has_value());
    CHECK(*opt == two);

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<char>());
    CHECK(test<char8_t>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    CHECK(test<wchar_t>());

    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
