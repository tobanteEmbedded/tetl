// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_DURATION_HPP
#define TETL_CHRONO_DURATION_HPP

#include <etl/_chrono/duration_values.hpp>
#include <etl/_chrono/treat_as_floating_point.hpp>
#include <etl/_cstdint/int_least_t.hpp>
#include <etl/_numeric/gcd.hpp>
#include <etl/_numeric/lcm.hpp>
#include <etl/_ratio/ratio.hpp>
#include <etl/_ratio/ratio_divide.hpp>
#include <etl/_type_traits/common_type.hpp>
#include <etl/_type_traits/is_convertible.hpp>

namespace etl::chrono {

/// \brief Class template etl::chrono::duration represents a time interval.
///
/// \details It consists of a count of ticks of type Rep and a tick period,
/// where the tick period is a compile-time rational constant representing the
/// number of seconds from one tick to the next. The only data stored in a
/// duration is a tick count of type Rep. If Rep is floating point, then the
/// duration can represent fractions of ticks. Period is included as part of the
/// duration's type, and is only used when converting between different
/// durations.
template <typename Rep, typename Period = etl::ratio<1>>
struct duration {
    /// \brief Rep, an arithmetic type representing the number of ticks.
    using rep = Rep;

    /// \brief A etl::ratio representing the tick period (i.e. the number of
    /// seconds per tick).
    using period = typename Period::type;

    /// \brief Constructs a new duration from one of several optional data
    /// sources. The default constructor is defaulted.
    constexpr duration() noexcept = default;

    /// \brief Constructs a new duration from one of several optional data
    /// sources. The copy constructor is defaulted (makes a bitwise copy of the
    /// tick count).
    constexpr duration(duration const&) noexcept = default;

    /// \brief Constructs a duration with r ticks.
    ///
    /// \details  Note that this constructor only participates in overload
    /// resolution if const Rep2& (the argument type) is implicitly convertible
    /// to rep (the type of this duration's ticks) and
    /// treat_as_floating_point<rep>::value is true, or
    /// treat_as_floating_point<Rep2>::value is false.
    ///
    /// That is, a duration with an integer tick count cannot be constructed
    /// from a floating-point value, but a duration with a floating-point tick
    /// count can be constructed from an integer value
    template <typename Rep2>
        requires(is_convertible_v<Rep2, rep> and (treat_as_floating_point_v<rep> or !treat_as_floating_point_v<Rep2>))
    constexpr explicit duration(Rep2 const& r) noexcept : _rep(r)
    {
    }

    /// \brief  Constructs a duration by converting d to an appropriate period
    /// and tick count, as if by duration_cast<duration>(d).count().
    ///
    /// \details In order to prevent truncation during conversion, this
    /// constructor only participates in overload resolution if computation of
    /// the conversion factor (by etl::ratio_divide<Period2, Period>) does not
    /// overflow and:
    ///
    /// treat_as_floating_point<rep>::value == true
    ///
    /// or both:
    ///
    /// ratio_divide<Period2, period>::den == 1, and
    /// treat_as_floating_point<Rep2>::value == false
    ///
    /// That is, either the duration uses floating-point ticks, or Period2 is
    /// exactly divisible by period
    template <typename Rep2, typename Period2>
        requires(
            treat_as_floating_point_v<rep>
            or (ratio_divide<Period2, period>::den == 1 and not treat_as_floating_point_v<Rep2>)
        )
    constexpr duration(duration<Rep2, Period2> const& other) noexcept
        : _rep(static_cast<Rep>(other.count() * ratio_divide<Period2, period>::num))
    {
    }

    /// \brief Assigns the contents of one duration to another.
    auto operator=(duration const& other) -> duration& = default;

    /// \brief Returns the number of ticks for this duration.
    [[nodiscard]] constexpr auto count() const -> rep { return _rep; }

    /// \brief Returns a zero-length duration.
    [[nodiscard]] static constexpr auto zero() noexcept -> duration
    {
        return duration(etl::chrono::duration_values<rep>::zero());
    }

    /// \brief Returns a duration with the lowest possible value.
    [[nodiscard]] static constexpr auto min() noexcept -> duration
    {
        return duration(etl::chrono::duration_values<rep>::min());
    }

    /// \brief Returns a duration with the largest possible value.
    [[nodiscard]] static constexpr auto max() noexcept -> duration
    {
        return duration(etl::chrono::duration_values<rep>::max());
    }

    /// \brief Implements unary plus and unary minus for the durations.
    [[nodiscard]] constexpr auto operator+() const -> etl::common_type_t<duration>
    {
        return etl::common_type_t<duration>(*this);
    }

    /// \brief Implements unary plus and unary minus for the durations.
    [[nodiscard]] constexpr auto operator-() const -> etl::common_type_t<duration>
    {
        return etl::common_type_t<duration>(-_rep);
    }

    /// \brief Increments or decrements the number of ticks for this duration.
    /// Equivalent to ++_rep; return *this;
    constexpr auto operator++() -> duration&
    {
        ++_rep;
        return *this;
    }

    /// \brief Increments or decrements the number of ticks for this duration.
    /// Equivalent to return duration(_rep++)
    constexpr auto operator++(int) -> duration { return duration(_rep++); }

    /// \brief Increments or decrements the number of ticks for this duration.
    /// Equivalent to --_rep; return *this;
    constexpr auto operator--() -> duration&
    {
        --_rep;
        return *this;
    }

    /// \brief Increments or decrements the number of ticks for this duration.
    /// Equivalent to return duration(_rep--);
    constexpr auto operator--(int) -> duration { return duration(_rep--); }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator+=(duration const& d) noexcept -> duration&
    {
        _rep += d.count();
        return *this;
    }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator-=(duration const& d) noexcept -> duration&
    {
        _rep -= d.count();
        return *this;
    }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator*=(rep const& rhs) noexcept -> duration&
    {
        _rep *= rhs;
        return *this;
    }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator/=(rep const& rhs) noexcept -> duration&
    {
        _rep /= rhs;
        return *this;
    }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator%=(rep const& rhs) noexcept -> duration&
    {
        _rep %= rhs;
        return *this;
    }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator%=(duration const& rhs) noexcept -> duration&
    {
        _rep %= rhs.count();
        return *this;
    }

private:
    rep _rep{};
};

} // namespace etl::chrono

namespace etl {

/// \brief Exposes the type named type, which is the common type of two
/// etl::chrono::durations, whose period is the greatest common divisor of
/// Period1 and Period2.
/// \details The period of the resulting duration can be computed by forming a
/// ratio of the greatest common divisor of Period1::num and Period2::num and
/// the least common multiple of Period1::den and Period2::den.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
struct common_type<chrono::duration<Rep1, Period1>, chrono::duration<Rep2, Period2>> {
private:
    static constexpr auto num = gcd(Period1::num, Period2::num);
    static constexpr auto den = lcm(Period1::den, Period2::den);

public:
    using type = chrono::duration<common_type_t<Rep1, Rep2>, ratio<num, den>>;
};

} // namespace etl

namespace etl::chrono {

/// \brief Performs basic arithmetic operations between two durations or between
/// a duration and a tick count.
///
/// \details Converts the two durations to their common type and creates a
/// duration whose tick count is the sum of the tick counts after conversion.
///
/// https://en.cppreference.com/w/cpp/chrono/duration/operator_arith4
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator+(duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs)
    -> common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>
{
    using CD = common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>;
    using CR = typename CD::rep;
    return CD(static_cast<CR>(CD(lhs).count() + CD(rhs).count()));
}

/// \brief Performs basic arithmetic operations between two durations or between
/// a duration and a tick count.
///
/// \details Converts the two durations to their common type and creates a
/// duration whose tick count is the rhs number of ticks subtracted from the lhs
/// number of ticks after conversion.
///
/// https://en.cppreference.com/w/cpp/chrono/duration/operator_arith4
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator-(duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs)
    -> common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>
{
    using CD = common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>;
    using CR = typename CD::rep;
    return CD(static_cast<CR>(CD(lhs).count() - CD(rhs).count()));
}

/// \brief Performs basic arithmetic operations between two durations or between
/// a duration and a tick count.
///
/// \details Converts the two durations to their common type and creates a
/// duration whose tick count is the rhs number of ticks subtracted from the lhs
/// number of ticks after conversion.
///
/// https://en.cppreference.com/w/cpp/chrono/duration/operator_arith4
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto
operator/(duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs) -> common_type_t<Rep1, Rep2>
{
    using CD = common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>;
    return CD(lhs).count() / CD(rhs).count();
}

/// \brief Performs basic arithmetic operations between two durations or between
/// a duration and a tick count.
///
/// \details Converts the two durations to their common type and creates a
/// duration whose tick count is the remainder of the tick counts after
/// conversion.
///
/// https://en.cppreference.com/w/cpp/chrono/duration/operator_arith4
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator%(duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs)
    -> common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>
{
    using CD = common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>;
    using CR = typename CD::rep;
    return CD(static_cast<CR>(CD(lhs).count() % CD(rhs).count()));
}

/// \brief Compares two durations. Checks if lhs and rhs are equal, i.e. the
/// number of ticks for the type common to both durations are equal.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator==(duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs) -> bool
{
    using common_t = typename etl::common_type<duration<Rep1, Period1>, duration<Rep2, Period2>>::type;
    return common_t(lhs).count() == common_t(rhs).count();
}

/// \brief Compares two durations. Checks if lhs and rhs are equal, i.e. the
/// number of ticks for the type common to both durations are equal.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator!=(duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs) -> bool
{
    return !(lhs == rhs);
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator<(duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs) -> bool
{
    using common_t = typename etl::common_type<duration<Rep1, Period1>, duration<Rep2, Period2>>::type;
    return common_t(lhs).count() < common_t(rhs).count();
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator<=(duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs) -> bool
{
    return !(rhs < lhs);
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator>(duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs) -> bool
{
    return rhs < lhs;
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator>=(duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs) -> bool
{
    return !(lhs < rhs);
}

/// \brief Signed integer type of at least 64 bits.
using nanoseconds = duration<int_least64_t, nano>;

/// \brief Signed integer type of at least 55 bits.
using microseconds = duration<int_least64_t, micro>;

/// \brief Signed integer type of at least 45 bits.
using milliseconds = duration<int_least64_t, milli>;

/// \brief Signed integer type of at least 35 bits.
using seconds = duration<int_least64_t>;

/// \brief Signed integer type of at least 29 bits.
using minutes = duration<int_least32_t, ratio<60>>;

/// \brief Signed integer type of at least 23 bits.
using hours = duration<int_least32_t, ratio<3600>>;

/// \brief Signed integer type of at least 25 bits.
using days = duration<int_least32_t, ratio<86400>>;

/// \brief Signed integer type of at least 22 bits.
using weeks = duration<int_least32_t, ratio<604800>>;

/// \brief Signed integer type of at least 20 bits.
using months = duration<int_least32_t, ratio<31556952>>;

/// \brief Signed integer type of at least 17 bits.
using years = duration<int_least32_t, ratio<2629746>>;

} // namespace etl::chrono

// NOLINTNEXTLINE(modernize-concat-nested-namespaces)
namespace etl {

inline namespace literals {
inline namespace chrono_literals {

/// \brief Forms a etl::chrono::duration literal representing hours.
/// Integer literal, returns exactly etl::chrono::hours(hrs).
constexpr auto operator""_h(unsigned long long h) -> etl::chrono::hours
{
    return etl::chrono::hours(static_cast<etl::chrono::hours::rep>(h));
}

/// \brief Forms a etl::chrono::duration literal representing hours.
/// Floating-point literal, returns a floating-point duration equivalent
/// to etl::chrono::hours.
constexpr auto operator""_h(long double h) -> etl::chrono::duration<long double, ratio<3600, 1>>
{
    return etl::chrono::duration<long double, etl::ratio<3600, 1>>(h);
}

/// \brief Forms a etl::chrono::duration literal representing minutes.
/// Integer literal, returns exactly etl::chrono::minutes(mins).
constexpr auto operator""_min(unsigned long long m) -> etl::chrono::minutes
{
    return etl::chrono::minutes(static_cast<etl::chrono::minutes::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing minutes.
/// Floating-point literal, returns a floating-point duration equivalent
/// to etl::chrono::minutes.
constexpr auto operator""_min(long double m) -> etl::chrono::duration<long double, etl::ratio<60, 1>>
{
    return etl::chrono::duration<long double, ratio<60, 1>>(m);
}

/// \brief Forms a etl::chrono::duration literal representing seconds.
/// Integer literal, returns exactly etl::chrono::seconds(mins).
constexpr auto operator""_s(unsigned long long m) -> etl::chrono::seconds
{
    return etl::chrono::seconds(static_cast<etl::chrono::seconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing seconds.
/// Floating-point literal, returns a floating-point duration equivalent
/// to etl::chrono::seconds.
constexpr auto operator""_s(long double m) -> etl::chrono::duration<long double>
{
    return etl::chrono::duration<long double>(m);
}

/// \brief Forms a etl::chrono::duration literal representing
/// milliseconds. Integer literal, returns exactly
/// etl::chrono::milliseconds(mins).
constexpr auto operator""_ms(unsigned long long m) -> etl::chrono::milliseconds
{
    return etl::chrono::milliseconds(static_cast<etl::chrono::milliseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing
/// milliseconds. Floating-point literal, returns a floating-point
/// duration equivalent to etl::chrono::milliseconds.
constexpr auto operator""_ms(long double m) -> etl::chrono::duration<long double, etl::milli>
{
    return etl::chrono::duration<long double, etl::milli>(m);
}

/// \brief Forms a etl::chrono::duration literal representing
/// microseconds. Integer literal, returns exactly
/// etl::chrono::microseconds(mins).
constexpr auto operator""_us(unsigned long long m) -> etl::chrono::microseconds
{
    return etl::chrono::microseconds(static_cast<etl::chrono::microseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing
/// microseconds. Floating-point literal, returns a floating-point
/// duration equivalent to etl::chrono::microseconds.
constexpr auto operator""_us(long double m) -> etl::chrono::duration<long double, etl::micro>
{
    return etl::chrono::duration<long double, etl::micro>(m);
}

/// \brief Forms a etl::chrono::duration literal representing
/// nanoseconds. Integer literal, returns exactly
/// etl::chrono::nanoseconds(mins).
constexpr auto operator""_ns(unsigned long long m) -> etl::chrono::nanoseconds
{
    return etl::chrono::nanoseconds(static_cast<etl::chrono::nanoseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing
/// nanoseconds. Floating-point literal, returns a floating-point
/// duration equivalent to etl::chrono::nanoseconds.
constexpr auto operator""_ns(long double m) -> etl::chrono::duration<long double, etl::nano>
{
    return etl::chrono::duration<long double, etl::nano>(m);
}

} // namespace chrono_literals
} // namespace literals
} // namespace etl

namespace etl::chrono {
using namespace etl::literals::chrono_literals;
} // namespace etl::chrono

#endif // TETL_CHRONO_DURATION_HPP
