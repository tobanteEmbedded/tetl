// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPARE_STRONG_ORDERING_HPP
#define TETL_COMPARE_STRONG_ORDERING_HPP

#include <etl/_compare/detail.hpp>
#include <etl/_compare/partial_ordering.hpp>
#include <etl/_compare/weak_ordering.hpp>
#include <etl/_cstddef/nullptr_t.hpp>

namespace etl {

/// \ingroup compare
struct strong_ordering {
    static strong_ordering const less;
    static strong_ordering const equal;
    static strong_ordering const equivalent;
    static strong_ordering const greater;

    [[nodiscard]] constexpr operator partial_ordering() const noexcept
    {
        return _value == 0 ? partial_ordering::equivalent
                           : (_value < 0 ? partial_ordering::less : partial_ordering::greater);
    }

    [[nodiscard]] constexpr operator weak_ordering() const noexcept
    {
        return _value == 0 ? weak_ordering::equivalent : (_value < 0 ? weak_ordering::less : weak_ordering::greater);
    }

    [[nodiscard]] friend constexpr auto operator==(strong_ordering, strong_ordering) noexcept -> bool = default;

    [[nodiscard]] friend constexpr auto operator==(strong_ordering v, nullptr_t) noexcept -> bool
    {
        return v._value == 0;
    }

    [[nodiscard]] friend constexpr auto operator<(strong_ordering v, nullptr_t) noexcept -> bool
    {
        return v._value < 0;
    }

    [[nodiscard]] friend constexpr auto operator<=(strong_ordering v, nullptr_t) noexcept -> bool
    {
        return v._value <= 0;
    }

    [[nodiscard]] friend constexpr auto operator>(strong_ordering v, nullptr_t) noexcept -> bool
    {
        return v._value > 0;
    }

    [[nodiscard]] friend constexpr auto operator>=(strong_ordering v, nullptr_t) noexcept -> bool
    {
        return v._value >= 0;
    }

    [[nodiscard]] friend constexpr auto operator<(nullptr_t, strong_ordering v) noexcept -> bool
    {
        return 0 < v._value;
    }

    [[nodiscard]] friend constexpr auto operator<=(nullptr_t, strong_ordering v) noexcept -> bool
    {
        return 0 <= v._value;
    }

    [[nodiscard]] friend constexpr auto operator>(nullptr_t, strong_ordering v) noexcept -> bool
    {
        return 0 > v._value;
    }

    [[nodiscard]] friend constexpr auto operator>=(nullptr_t, strong_ordering v) noexcept -> bool
    {
        return 0 >= v._value;
    }

    [[nodiscard]] friend constexpr auto operator<=>(strong_ordering v, nullptr_t) noexcept -> strong_ordering
    {
        return v;
    }

    [[nodiscard]] friend constexpr auto operator<=>(nullptr_t, strong_ordering v) noexcept -> strong_ordering
    {
        return v < nullptr ? strong_ordering::greater : (v > nullptr ? strong_ordering::less : v);
    }

private:
    constexpr explicit strong_ordering(detail::order_result v) noexcept : _value{static_cast<int8_t>(v)} { }

    int8_t _value;
};

inline constexpr strong_ordering strong_ordering::less{detail::order_result::less};
inline constexpr strong_ordering strong_ordering::equal{detail::order_result::equal};
inline constexpr strong_ordering strong_ordering::equivalent{detail::order_result::equal};
inline constexpr strong_ordering strong_ordering::greater{detail::order_result::greater};

} // namespace etl

#endif // TETL_COMPARE_STRONG_ORDERING_HPP
