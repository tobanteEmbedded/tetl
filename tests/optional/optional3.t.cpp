// SPDX-License-Identifier: BSL-1.0

#include <etl/optional.hpp>

#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T>
struct wrapper {
    T value;
    [[nodiscard]] explicit(false) constexpr operator T() const noexcept { return value; }
};

template <typename T>
constexpr auto test() -> bool
{
    CHECK_SAME_TYPE(typename etl::optional<T>::value_type, T);
    CHECK(etl::is_trivially_destructible_v<etl::optional<T>>);

    // Empty (implicit)
    {
        auto const opt = etl::optional<T>{};
        CHECK_FALSE(static_cast<bool>(opt));
        CHECK_FALSE(opt.has_value());
    }

    // Empty (explicit)
    {
        auto const opt = etl::optional<T>{etl::nullopt};
        CHECK_FALSE(opt.has_value());
    }

    // Copy from optional<U>
    {
        auto other = etl::optional<wrapper<T>>{};
        auto opt   = etl::optional<T>{other};
        CHECK_FALSE(opt.has_value());
    }

    {
        auto other = etl::optional{wrapper<T>{T(42)}};
        auto opt   = etl::optional<T>{other};
        CHECK(opt.has_value());
        CHECK(*opt == T(42));
    }

    // Move from optional<U>
    {
        auto other     = etl::optional<wrapper<T>>{};
        auto const opt = etl::optional<T>{etl::move(other)};
        CHECK_FALSE(opt.has_value());
    }

    {
        auto other     = etl::optional{wrapper<T>{T(42)}};
        auto const opt = etl::optional<T>{etl::move(other)};
        CHECK(opt.has_value());
        CHECK(*opt == T(42));
    }

    // In-place
    {
        auto const opt = etl::optional<T>{etl::in_place, T(99)};
        CHECK(opt.has_value());
        CHECK(*opt == T(99));
    }

    // From U implicit
    {
        etl::optional<T> const opt = wrapper<T>(T(99));
        CHECK(opt.has_value());
        CHECK(*opt == T(99));
    }

    // From U explicit
    {
        auto const opt = etl::optional<T>{wrapper<T>(T(99))};
        CHECK(opt.has_value());
        CHECK(*opt == T(99));
    }

    // Assign nullopt
    {
        auto opt = etl::optional<T>{};
        opt      = etl::nullopt;
        CHECK_FALSE(opt.has_value());
    }

    // Assign U
    {
        auto opt = etl::optional<T>{};
        opt      = wrapper<T>(T(42));
        CHECK(opt.has_value());
        CHECK(*opt == T(42));
    }

    // Assign optional<U>
    {
        auto opt   = etl::optional<T>{};
        auto other = etl::optional{wrapper<T>(T(42))};
        opt        = other;
        CHECK(opt.has_value());
        CHECK(*opt == T(42));
    }

    // Assign optional<U>
    {
        auto opt   = etl::optional<T>{};
        auto other = etl::optional<wrapper<T>>{etl::nullopt};
        opt        = other;
        CHECK_FALSE(opt.has_value());
    }

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
#if defined(_MSC_VER) and not defined(__clang__)
    CHECK(test_all());
#else
    STATIC_CHECK(test_all());
#endif

    return 0;
}
