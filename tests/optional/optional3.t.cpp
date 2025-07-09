// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.optional;
import etl.type_traits;
import etl.utility;
#else
    #include <etl/optional.hpp>
    #include <etl/type_traits.hpp>
    #include <etl/utility.hpp>
#endif

namespace {

template <typename T>
struct Wrapper {
    explicit constexpr Wrapper(T val)
        : value{val}
    {
    }

    [[nodiscard]] explicit(false) constexpr operator T() const noexcept { return value; }

    friend constexpr auto operator==(Wrapper lhs, T rhs) noexcept -> bool { return lhs.value == rhs; }
    friend constexpr auto operator==(T lhs, Wrapper rhs) noexcept -> bool { return lhs == rhs.value; }

    friend constexpr auto operator<(Wrapper lhs, T rhs) noexcept -> bool { return lhs.value < rhs; }
    friend constexpr auto operator<(T lhs, Wrapper rhs) noexcept -> bool { return lhs < rhs.value; }

    T value;
};

template <typename T>
constexpr auto test() -> bool
{
    using etl::optional;

    CHECK_SAME_TYPE(typename optional<T>::value_type, T);
    CHECK(etl::is_trivially_destructible_v<optional<T>>);

    // Empty (implicit)
    {
        auto const opt = optional<T>{};
        CHECK_FALSE(static_cast<bool>(opt));
        CHECK_FALSE(opt.has_value());
    }

    // Empty (explicit)
    {
        auto const opt = optional<T>{etl::nullopt};
        CHECK_FALSE(opt.has_value());
    }

    // Copy from optional<U>
    {
        auto other = optional<Wrapper<T>>{};
        auto opt   = optional<T>{other};
        CHECK_FALSE(opt.has_value());
    }

    {
        auto other = optional{Wrapper<T>{T(42)}};
        auto opt   = optional<T>{other};
        CHECK(opt.has_value());
        CHECK(*opt == T(42));
    }

    // Move from optional<U>
    {
        auto other     = optional<Wrapper<T>>{};
        auto const opt = optional<T>{etl::move(other)};
        CHECK_FALSE(opt.has_value());
    }

    {
        auto other     = optional{Wrapper<T>{T(42)}};
        auto const opt = optional<T>{etl::move(other)};
        CHECK(opt.has_value());
        CHECK(*opt == T(42));
    }

    // In-place
    {
        auto const opt = optional<T>{etl::in_place, T(99)};
        CHECK(opt.has_value());
        CHECK(*opt == T(99));
    }

    // From U implicit
    {
        optional<T> const opt = Wrapper<T>{T(99)};
        CHECK(opt.has_value());
        CHECK(*opt == T(99));
    }

    // From U explicit
    {
        auto const opt = optional<T>{Wrapper<T>{T(99)}};
        CHECK(opt.has_value());
        CHECK(*opt == T(99));
    }

    // Assign nullopt
    {
        auto opt = optional<T>{};
        opt      = etl::nullopt;
        CHECK_FALSE(opt.has_value());
    }

    // Assign U
    {
        auto opt   = optional<T>{};
        auto other = Wrapper<T>{T(42)};
        opt        = other;
        CHECK(opt.has_value());
        CHECK(*opt == T(42));
    }

    // Assign optional<U>
    {
        auto opt   = optional<T>{};
        auto other = optional{Wrapper<T>{T(42)}};
        opt        = other;
        CHECK(opt.has_value());
        CHECK(*opt == T(42));
    }

    // Assign optional<U>
    {
        auto opt   = optional<T>{};
        auto other = optional<Wrapper<T>>{etl::nullopt};
        opt        = other;
        CHECK_FALSE(opt.has_value());
    }

    // Compare Equal
    {
        CHECK(optional<T>{} == optional<T>{});
        CHECK(optional<T>{T(42)} == optional<T>{T(42)});
        CHECK_FALSE(optional<T>{T(42)} == optional<T>{T(99)});

        CHECK_FALSE(optional<T>{} == optional<T>{T(99)});
        CHECK_FALSE(optional<T>{T(42)} == optional<T>{});

        CHECK_FALSE(T(42) == optional<T>{});
        CHECK_FALSE(optional<T>{} == T(42));

        CHECK(optional<T>{} == optional<Wrapper<T>>{});
        CHECK(optional<T>{T(42)} == optional<Wrapper<T>>{T(42)});
        CHECK(Wrapper<T>(42) == optional{T(42)});
        CHECK_FALSE(optional<T>{T(42)} == optional<Wrapper<T>>{T(99)});
        CHECK_FALSE(optional<T>{} == optional<Wrapper<T>>{T(99)});
        CHECK_FALSE(optional<T>{T(42)} == optional<Wrapper<T>>{});
        CHECK_FALSE(optional<T>{} == Wrapper<T>(42));
        CHECK_FALSE(Wrapper<T>(42) == optional<T>{});

        CHECK(T(42) != optional<T>{});
        CHECK(Wrapper<T>(42) != optional{T(99)});
        CHECK(optional{T(99)} != T(42));
        CHECK(optional{T(99)} != Wrapper<T>(42));
    }

    // Compare Less
    {
        CHECK(optional{T(42)} < optional{T(99)});
        CHECK(optional{T(42)} < optional<Wrapper<T>>{T(99)});
        CHECK(optional<Wrapper<T>>{T(42)} < optional{T(99)});
        CHECK(optional<T>{} < optional<T>{T(42)});
        CHECK(optional<T>{} < optional<Wrapper<T>>{T(42)});
        CHECK_FALSE(optional<T>{T(42)} < optional<T>{});
        CHECK_FALSE(optional<T>{T(42)} < optional<Wrapper<T>>{});

        CHECK(optional{T(42)} < T(99));
        CHECK(optional{T(42)} < Wrapper<T>(99));
        CHECK(optional{T()} < Wrapper<T>(99));
        CHECK_FALSE(optional{T(99)} < Wrapper<T>(99));
    }

    // Compare Less-Equal
    {
        CHECK(optional{T(42)} <= optional{T(99)});
        CHECK(optional{T(42)} <= optional<Wrapper<T>>{T(99)});
        CHECK(optional<Wrapper<T>>{T(42)} <= optional{T(99)});
        CHECK(optional<T>{} <= optional<T>{T(42)});
        CHECK(optional<T>{} <= optional<Wrapper<T>>{T(42)});
        CHECK_FALSE(optional<T>{T(42)} <= optional<T>{});
        CHECK_FALSE(optional<T>{T(42)} <= optional<Wrapper<T>>{});

        CHECK(optional{T(42)} <= T(99));
        CHECK(optional{T(42)} <= Wrapper<T>(99));
        CHECK(optional{T()} <= Wrapper<T>(99));
        CHECK_FALSE(optional<T>{T(99)} <= Wrapper<T>(42));
    }

    // Compare Greater
    {
        CHECK(optional{T(99)} > optional{T(42)});
        CHECK(optional{T(99)} > optional<Wrapper<T>>{T(42)});
        CHECK(optional<Wrapper<T>>{T(99)} > optional{T(42)});
        CHECK(optional<T>{T(99)} > optional<T>{});
        CHECK(optional<T>{T(99)} > optional<Wrapper<T>>{});
        CHECK_FALSE(optional<T>{} > optional<T>{T(99)});
        CHECK_FALSE(optional<T>{} > optional<Wrapper<T>>{T(99)});

        CHECK(optional<T>{T(99)} > Wrapper<T>(42));
        CHECK_FALSE(optional{T(42)} > T(99));
        CHECK_FALSE(optional{T(42)} > Wrapper<T>(99));
        CHECK_FALSE(optional{T()} > Wrapper<T>(99));
    }

    // Compare Greater-Equal
    {
        CHECK(optional{T(99)} >= optional{T(42)});
        CHECK(optional{T(99)} >= optional<Wrapper<T>>{T(42)});
        CHECK(optional<Wrapper<T>>{T(99)} >= optional{T(42)});
        CHECK(optional<T>{T(99)} >= optional<T>{});
        CHECK(optional<T>{T(99)} >= optional<Wrapper<T>>{});
        CHECK_FALSE(optional<T>{} >= optional<T>{T(99)});
        CHECK_FALSE(optional<T>{} >= optional<Wrapper<T>>{T(99)});

        CHECK(optional<T>{T(99)} >= Wrapper<T>(42));
        CHECK(optional<T>{T(99)} >= Wrapper<T>(99));
        CHECK_FALSE(optional{T(42)} >= T(99));
        CHECK_FALSE(optional{T(42)} >= Wrapper<T>(99));
        CHECK_FALSE(optional{T()} >= Wrapper<T>(99));
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
