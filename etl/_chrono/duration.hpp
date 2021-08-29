/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_DURATION_HPP
#define TETL_CHRONO_DURATION_HPP

#include "etl/_chrono/duration_values.hpp"
#include "etl/_chrono/treat_as_floating_point.hpp"
#include "etl/_concepts/requires.hpp"
#include "etl/_numeric/gcd.hpp"
#include "etl/_numeric/lcm.hpp"
#include "etl/_ratio/ratio.hpp"
#include "etl/_ratio/ratio_divide.hpp"
#include "etl/_type_traits/common_type.hpp"
#include "etl/_type_traits/is_convertible.hpp"

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
    template <typename Rep2, TETL_REQUIRES_((is_convertible_v<Rep2, rep>)&&(
                                 treat_as_floating_point_v<
                                     rep> || !treat_as_floating_point_v<Rep2>))>
    constexpr explicit duration(Rep2 const& r) noexcept : rep_(r)
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
    template <typename Rep2, typename Period2,
        TETL_REQUIRES_((treat_as_floating_point_v<rep>)
                       || (ratio_divide<Period2, period>::den == 1
                           && !treat_as_floating_point_v<Rep2>))>
    constexpr duration(duration<Rep2, Period2> const& other) noexcept
        : rep_(static_cast<Rep>(
            other.count() * ratio_divide<Period2, period>::num))
    {
    }

    /// \brief Assigns the contents of one duration to another.
    auto operator=(duration const& other) -> duration& = default;

    /// \brief Returns the number of ticks for this duration.
    [[nodiscard]] constexpr auto count() const -> rep { return rep_; }

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
    [[nodiscard]] constexpr auto operator+() const
        -> etl::common_type_t<duration>
    {
        return etl::common_type_t<duration>(*this);
    }

    /// \brief Implements unary plus and unary minus for the durations.
    [[nodiscard]] constexpr auto operator-() const
        -> etl::common_type_t<duration>
    {
        return etl::common_type_t<duration>(-rep_);
    }

    /// \brief Increments or decrements the number of ticks for this duration.
    /// Equivalent to ++rep_; return *this;
    constexpr auto operator++() -> duration&
    {
        ++rep_;
        return *this;
    }

    /// \brief Increments or decrements the number of ticks for this duration.
    /// Equivalent to return duration(rep_++)
    constexpr auto operator++(int) -> duration { return duration(rep_++); }

    /// \brief Increments or decrements the number of ticks for this duration.
    /// Equivalent to --rep_; return *this;
    constexpr auto operator--() -> duration&
    {
        --rep_;
        return *this;
    }

    /// \brief Increments or decrements the number of ticks for this duration.
    /// Equivalent to return duration(rep_--);
    constexpr auto operator--(int) -> duration { return duration(rep_--); }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator+=(duration const& d) noexcept -> duration&
    {
        rep_ += d.count();
        return *this;
    }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator-=(duration const& d) noexcept -> duration&
    {
        rep_ -= d.count();
        return *this;
    }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator*=(rep const& rhs) noexcept -> duration&
    {
        rep_ *= rhs;
        return *this;
    }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator/=(rep const& rhs) noexcept -> duration&
    {
        rep_ /= rhs;
        return *this;
    }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator%=(rep const& rhs) noexcept -> duration&
    {
        rep_ %= rhs;
        return *this;
    }

    /// \brief Performs compound assignments between two durations with the same
    /// period or between a duration and a tick count value.
    constexpr auto operator%=(duration const& rhs) noexcept -> duration&
    {
        rep_ %= rhs.count();
        return *this;
    }

private:
    rep rep_ {};
};

/// \brief Performs basic arithmetic operations between two durations or between
/// a duration and a tick count.
///
/// \details Converts the two durations to their common type and creates a
/// duration whose tick count is the sum of the tick counts after conversion.
///
/// https://en.cppreference.com/w/cpp/chrono/duration/operator_arith4
///
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator+(
    duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs)
    -> common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>
{
    using CD = common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>;
    return CD(CD(lhs).count() + CD(rhs).count());
}

/// \brief Performs basic arithmetic operations between two durations or between
/// a duration and a tick count.
///
/// \details Converts the two durations to their common type and creates a
/// duration whose tick count is the rhs number of ticks subtracted from the lhs
/// number of ticks after conversion.
///
/// https://en.cppreference.com/w/cpp/chrono/duration/operator_arith4
///
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator-(
    duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs)
    -> common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>
{
    using CD = common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>;
    return CD(CD(lhs).count() - CD(rhs).count());
}

/// \brief Performs basic arithmetic operations between two durations or between
/// a duration and a tick count.
///
/// \details Converts the two durations to their common type and creates a
/// duration whose tick count is the rhs number of ticks subtracted from the lhs
/// number of ticks after conversion.
///
/// https://en.cppreference.com/w/cpp/chrono/duration/operator_arith4
///
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator/(duration<Rep1, Period1> const& lhs,
    duration<Rep2, Period2> const& rhs) -> common_type_t<Rep1, Rep2>
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
///
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator%(
    duration<Rep1, Period1> const& lhs, duration<Rep2, Period2> const& rhs)
    -> common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>
{
    using CD = common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>;
    return CD(CD(lhs).count() % CD(rhs).count());
}

/// \brief Compares two durations. Checks if lhs and rhs are equal, i.e. the
/// number of ticks for the type common to both durations are equal.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator==(duration<Rep1, Period1> const& lhs,
    duration<Rep2, Period2> const& rhs) -> bool
{
    using common_t = typename etl::common_type<duration<Rep1, Period1>,
        duration<Rep2, Period2>>::type;

    return common_t(lhs).count() == common_t(rhs).count();
}

/// \brief Compares two durations. Checks if lhs and rhs are equal, i.e. the
/// number of ticks for the type common to both durations are equal.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator!=(duration<Rep1, Period1> const& lhs,
    duration<Rep2, Period2> const& rhs) -> bool
{
    return !(lhs == rhs);
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator<(duration<Rep1, Period1> const& lhs,
    duration<Rep2, Period2> const& rhs) -> bool
{
    using common_t = typename etl::common_type<duration<Rep1, Period1>,
        duration<Rep2, Period2>>::type;
    return common_t(lhs).count() < common_t(rhs).count();
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator<=(duration<Rep1, Period1> const& lhs,
    duration<Rep2, Period2> const& rhs) -> bool
{
    return !(rhs < lhs);
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator>(duration<Rep1, Period1> const& lhs,
    duration<Rep2, Period2> const& rhs) -> bool
{
    return rhs < lhs;
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator>=(duration<Rep1, Period1> const& lhs,
    duration<Rep2, Period2> const& rhs) -> bool
{
    return !(lhs < rhs);
}

/// \brief Signed integer type of at least 64 bits.
/// \group duration_typedefs
using nanoseconds = duration<long long, nano>;

/// \brief Signed integer type of at least 55 bits.
/// \group duration_typedefs
using microseconds = duration<long long, micro>;

/// \brief Signed integer type of at least 45 bits.
/// \group duration_typedefs
using milliseconds = duration<long long, milli>;

/// \brief Signed integer type of at least 35 bits.
/// \group duration_typedefs
using seconds = duration<long long>;

/// \brief Signed integer type of at least 29 bits.
/// \group duration_typedefs
using minutes = duration<int, ratio<60>>;

/// \brief Signed integer type of at least 23 bits.
/// \group duration_typedefs
using hours = duration<int, ratio<3600>>;

/// \brief Signed integer type of at least 25 bits.
/// \group duration_typedefs
using days = duration<int, ratio<86400>>;

/// \brief Signed integer type of at least 22 bits.
/// \group duration_typedefs
using weeks = duration<int, ratio<604800>>;

/// \brief Signed integer type of at least 17 bits.
/// \group duration_typedefs
using years = duration<int, ratio<2629746>>;

/// \brief Signed integer type of at least 20 bits.
/// \group duration_typedefs
using months = duration<int, ratio<31556952>>;

} // namespace etl::chrono

namespace etl {
/// \brief Exposes the type named type, which is the common type of two
/// etl::chrono::durations, whose period is the greatest common divisor of
/// Period1 and Period2.
/// \details The period of the resulting duration can be computed by forming a
/// ratio of the greatest common divisor of Period1::num and Period2::num and
/// the least common multiple of Period1::den and Period2::den.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
struct common_type<chrono::duration<Rep1, Period1>,
    chrono::duration<Rep2, Period2>> {
private:
    static constexpr auto num = gcd(Period1::num, Period2::num);
    static constexpr auto den = lcm(Period1::den, Period2::den);

public:
    using type = chrono::duration<common_type_t<Rep1, Rep2>, ratio<num, den>>;
};
} // namespace etl

#endif // TETL_CHRONO_DURATION_HPP