// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

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
struct is_duration : ::etl::false_type {
};

template <typename Rep, typename Period>
struct is_duration<::etl::chrono::duration<Rep, Period>> : ::etl::true_type {
};

template <typename T>
inline constexpr auto is_duration_v = is_duration<T>::value;

template <typename ToDuration, typename CF, typename CR, bool NumIsOne = false,
    bool DenIsOne = false>
struct duration_cast_impl {
    template <typename Rep, typename Period>
    [[nodiscard]] static constexpr auto
    cast(duration<Rep, Period> const& duration) noexcept(
        is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>)
        -> ToDuration
    {
        using to_rep = typename ToDuration::rep;
        return ToDuration(static_cast<to_rep>(static_cast<CR>(duration.count())
                                              * static_cast<CR>(CF::num)
                                              / static_cast<CR>(CF::den)));
    }
};

template <typename ToDuration, typename CF, typename CR>
struct duration_cast_impl<ToDuration, CF, CR, true, false> {
    template <typename Rep, typename Period>
    [[nodiscard]] static constexpr auto
    cast(duration<Rep, Period> const& duration) noexcept(
        is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>)
        -> ToDuration
    {
        using to_rep = typename ToDuration::rep;
        return ToDuration(static_cast<to_rep>(
            static_cast<CR>(duration.count()) / static_cast<CR>(CF::den)));
    }
};

template <typename ToDuration, typename CF, typename CR>
struct duration_cast_impl<ToDuration, CF, CR, false, true> {
    template <typename Rep, typename Period>
    [[nodiscard]] static constexpr auto
    cast(duration<Rep, Period> const& duration) noexcept(
        is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>)
        -> ToDuration
    {
        using to_rep = typename ToDuration::rep;
        return ToDuration(static_cast<to_rep>(
            static_cast<CR>(duration.count()) * static_cast<CR>(CF::num)));
    }
};

template <typename ToDuration, typename CF, typename CR>
struct duration_cast_impl<ToDuration, CF, CR, true, true> {
    template <typename Rep, typename Period>
    [[nodiscard]] static constexpr auto
    cast(duration<Rep, Period> const& duration) noexcept(
        is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>)
        -> ToDuration
    {
        using to_rep = typename ToDuration::rep;
        return ToDuration(static_cast<to_rep>(duration.count()));
    }
};

} // namespace detail

/// \brief Converts a duration to a duration of different type ToDur.
template <typename ToDur, typename Rep, typename Period,
    TETL_REQUIRES_(detail::is_duration_v<ToDur>)>
[[nodiscard]] constexpr auto
duration_cast(duration<Rep, Period> const& duration) noexcept(
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