// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPARE_WEAK_ORDERING_HPP
#define TETL_COMPARE_WEAK_ORDERING_HPP

#include <etl/_compare/detail.hpp>
#include <etl/_compare/partial_ordering.hpp>
#include <etl/_cstddef/nullptr_t.hpp>

namespace etl {

struct weak_ordering {

    static weak_ordering const less;
    static weak_ordering const equivalent;
    static weak_ordering const greater;

    constexpr operator partial_ordering() const noexcept
    {
        return _value == 0 ? partial_ordering::equivalent
                           : (_value < 0 ? partial_ordering::less : partial_ordering::greater);
    }

    [[nodiscard]] friend constexpr auto operator==(weak_ordering, weak_ordering) noexcept -> bool = default;

    [[nodiscard]] friend constexpr auto operator==(weak_ordering v, nullptr_t) noexcept -> bool
    {
        return v._value == 0;
    }

    [[nodiscard]] friend constexpr auto operator<(weak_ordering v, nullptr_t) noexcept -> bool { return v._value < 0; }

    [[nodiscard]] friend constexpr auto operator<=(weak_ordering v, nullptr_t) noexcept -> bool
    {
        return v._value <= 0;
    }

    [[nodiscard]] friend constexpr auto operator>(weak_ordering v, nullptr_t) noexcept -> bool { return v._value > 0; }

    [[nodiscard]] friend constexpr auto operator>=(weak_ordering v, nullptr_t) noexcept -> bool
    {
        return v._value >= 0;
    }

    [[nodiscard]] friend constexpr auto operator<(nullptr_t, weak_ordering v) noexcept -> bool { return 0 < v._value; }

    [[nodiscard]] friend constexpr auto operator<=(nullptr_t, weak_ordering v) noexcept -> bool
    {
        return 0 <= v._value;
    }

    [[nodiscard]] friend constexpr auto operator>(nullptr_t, weak_ordering v) noexcept -> bool { return 0 > v._value; }

    [[nodiscard]] friend constexpr auto operator>=(nullptr_t, weak_ordering v) noexcept -> bool
    {
        return 0 >= v._value;
    }

    [[nodiscard]] friend constexpr auto operator<=>(weak_ordering v, nullptr_t) noexcept -> weak_ordering { return v; }

    [[nodiscard]] friend constexpr auto operator<=>(nullptr_t, weak_ordering v) noexcept -> weak_ordering
    {
        return v < nullptr ? weak_ordering::greater : (v > nullptr ? weak_ordering::less : v);
    }

private:
    explicit constexpr weak_ordering(detail::order_result v) noexcept : _value{static_cast<int8_t>(v)} { }

    int8_t _value;
};

inline constexpr weak_ordering weak_ordering::less{detail::order_result::less};
inline constexpr weak_ordering weak_ordering::equivalent{detail::order_result::equal};
inline constexpr weak_ordering weak_ordering::greater{detail::order_result::greater};

} // namespace etl

#endif // TETL_COMPARE_WEAK_ORDERING_HPP
