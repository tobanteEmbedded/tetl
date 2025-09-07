// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_RANDOM_UNIFORM_INT_DISTRIBUTION_HPP
#define TETL_RANDOM_UNIFORM_INT_DISTRIBUTION_HPP

#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \ingroup random
template <typename IntType = int>
struct uniform_int_distribution {
    using result_type = IntType;

    struct param_type {
        using distribution_type = uniform_int_distribution;

        constexpr param_type() noexcept = default;

        explicit constexpr param_type(result_type min, result_type max = result_type(1)) noexcept
            : _min{min}
            , _max{max}
        {
        }

        [[nodiscard]] constexpr auto a() const noexcept -> result_type
        {
            return _min;
        }

        [[nodiscard]] constexpr auto b() const noexcept -> result_type
        {
            return _max;
        }

        [[nodiscard]] friend constexpr auto operator==(param_type const& lhs, param_type const& rhs) noexcept -> bool
        {
            return (lhs._min == rhs._min) and (lhs._max == rhs._max);
        }

    private:
        result_type _min{0};
        result_type _max{numeric_limits<result_type>::max()};
    };

    constexpr uniform_int_distribution()
        : uniform_int_distribution{0}
    {
    }

    explicit constexpr uniform_int_distribution(param_type const& parm)
        : _param{parm}
    {
    }

    explicit constexpr uniform_int_distribution(IntType a, IntType b = numeric_limits<IntType>::max())
        : uniform_int_distribution(param_type{a, b})
    {
    }

    constexpr auto param(param_type const& parm) -> void
    {
        _param = parm;
    }

    [[nodiscard]] constexpr auto param() const -> param_type
    {
        return _param;
    }

    [[nodiscard]] constexpr auto a() const -> result_type
    {
        return _param.a();
    }

    [[nodiscard]] constexpr auto b() const -> result_type
    {
        return _param.b();
    }

    [[nodiscard]] constexpr auto min() const -> result_type
    {
        return a();
    }

    [[nodiscard]] constexpr auto max() const -> result_type
    {
        return b();
    }

    constexpr auto reset() -> void
    {
        (void)this;
    }

    template <typename URBG>
    [[nodiscard]] constexpr auto operator()(URBG& g) noexcept(noexcept(g())) -> result_type
    {
        return (*this)(g, _param);
    }

    template <typename URBG>
    [[nodiscard]] constexpr auto operator()(URBG& g, param_type const& parm) noexcept(noexcept(g())) -> result_type
    {
        auto const random = g();
        auto const range  = static_cast<decltype(g())>(parm.b() - parm.a());
        return static_cast<result_type>(parm.a() + static_cast<result_type>(random % range));
    }

    friend constexpr auto operator==(uniform_int_distribution const& x, uniform_int_distribution const& y) -> bool
    {
        return x.param() == y.param();
    }

private:
    param_type _param;
};

} // namespace etl

#endif // TETL_RANDOM_UNIFORM_INT_DISTRIBUTION_HPP
