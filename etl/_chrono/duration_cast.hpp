/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_DURATION_CAST_HPP
#define TETL_CHRONO_DURATION_CAST_HPP

#include "etl/_chrono/duration.hpp"
#include "etl/_chrono/treat_as_floating_point.hpp"
#include "etl/_concepts/requires.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/common_type.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"

namespace etl::chrono {

namespace detail {
template <typename T>
struct is_duration : etl::false_type {
};

template <typename Rep, typename Period>
struct is_duration<etl::chrono::duration<Rep, Period>> : etl::true_type {
};

template <typename T>
inline constexpr auto is_duration_v = is_duration<T>::value;

template <typename ToDuration, typename CF, typename CR, bool NumIsOne = false, bool DenIsOne = false>
struct duration_cast_impl {
    template <typename Rep, typename Period>
    [[nodiscard]] static constexpr auto cast(duration<Rep, Period> const& duration) noexcept(
        is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>) -> ToDuration
    {
        using to_rep = typename ToDuration::rep;
        return ToDuration(static_cast<to_rep>(
            static_cast<CR>(duration.count()) * static_cast<CR>(CF::num) / static_cast<CR>(CF::den)));
    }
};

template <typename ToDuration, typename CF, typename CR>
struct duration_cast_impl<ToDuration, CF, CR, true, false> {
    template <typename Rep, typename Period>
    [[nodiscard]] static constexpr auto cast(duration<Rep, Period> const& duration) noexcept(
        is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>) -> ToDuration
    {
        using to_rep = typename ToDuration::rep;
        return ToDuration(static_cast<to_rep>(static_cast<CR>(duration.count()) / static_cast<CR>(CF::den)));
    }
};

template <typename ToDuration, typename CF, typename CR>
struct duration_cast_impl<ToDuration, CF, CR, false, true> {
    template <typename Rep, typename Period>
    [[nodiscard]] static constexpr auto cast(duration<Rep, Period> const& duration) noexcept(
        is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>) -> ToDuration
    {
        using to_rep = typename ToDuration::rep;
        return ToDuration(static_cast<to_rep>(static_cast<CR>(duration.count()) * static_cast<CR>(CF::num)));
    }
};

template <typename ToDuration, typename CF, typename CR>
struct duration_cast_impl<ToDuration, CF, CR, true, true> {
    template <typename Rep, typename Period>
    [[nodiscard]] static constexpr auto cast(duration<Rep, Period> const& duration) noexcept(
        is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>) -> ToDuration
    {
        using to_rep = typename ToDuration::rep;
        return ToDuration(static_cast<to_rep>(duration.count()));
    }
};

} // namespace detail

/// \brief Converts a duration to a duration of different type ToDur.
template <typename ToDur, typename Rep, typename Period, TETL_REQUIRES_(detail::is_duration_v<ToDur>)>
[[nodiscard]] constexpr auto duration_cast(duration<Rep, Period> const& duration) noexcept(
    is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDur::rep>) -> ToDur
{
    using detail::duration_cast_impl;
    using cf   = ratio_divide<Period, typename ToDur::period>;
    using cr   = common_type_t<typename ToDur::rep, Rep, intmax_t>;
    using impl = duration_cast_impl<ToDur, cf, cr, cf::num == 1, cf::den == 1>;
    return impl::cast(duration);
}

} // namespace etl::chrono

#endif // TETL_CHRONO_DURATION_CAST_HPP
