// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANDOM_UNIFORM_REAL_DISTRIBUTION_HPP
#define TETL_RANDOM_UNIFORM_REAL_DISTRIBUTION_HPP

#include <etl/_limits/numeric_limits.hpp>
#include <etl/_random/generate_canonical.hpp>

namespace etl {

template <typename RealType = double>
struct uniform_real_distribution {
    using result_type = RealType;

    struct param_type {
        using distribution_type = uniform_real_distribution;

        constexpr param_type() noexcept = default;
        explicit constexpr param_type(result_type min, result_type max = result_type(1)) noexcept
            : min_ { min }, max_ { max }
        {
        }

        [[nodiscard]] constexpr auto a() const noexcept -> result_type { return min_; }
        [[nodiscard]] constexpr auto b() const noexcept -> result_type { return max_; }

        [[nodiscard]] friend constexpr auto operator==(param_type const& lhs, param_type const& rhs) noexcept -> bool
        {
            return (lhs.min_ == rhs.min_) and (lhs.max_ == rhs.max_);
        }

    private:
        result_type min_ { 0 };
        result_type max_ { 1 };
    };

    constexpr uniform_real_distribution() : uniform_real_distribution { static_cast<RealType>(0) } { }

    explicit constexpr uniform_real_distribution(param_type const& parm) : param_ { parm } { }

    explicit constexpr uniform_real_distribution(RealType a, RealType b = RealType(1))
        : uniform_real_distribution { param_type { a, b } }
    {
    }

    constexpr auto param(param_type const& parm) -> void { param_ = parm; }
    [[nodiscard]] constexpr auto param() const -> param_type { return param_; }

    [[nodiscard]] constexpr auto a() const -> result_type { return param_.a(); }
    [[nodiscard]] constexpr auto b() const -> result_type { return param_.b(); }

    [[nodiscard]] constexpr auto min() const -> result_type { return a(); }
    [[nodiscard]] constexpr auto max() const -> result_type { return b(); }

    constexpr auto reset() -> void { (void)this; }

    template <typename URBG>
    [[nodiscard]] constexpr auto operator()(URBG& g) noexcept(noexcept(g())) -> result_type
    {
        return (*this)(g, param_);
    }

    template <typename URBG>
    [[nodiscard]] constexpr auto operator()(URBG& g, param_type const& parm) noexcept(noexcept(g())) -> result_type
    {
        constexpr auto digits  = static_cast<size_t>(numeric_limits<RealType>::digits);
        constexpr auto bits    = ~size_t { 0 };
        constexpr auto minBits = digits < bits ? digits : bits;
        static_assert(minBits <= 64);

        // x = a + u * (b - a)
        auto const a = parm.a();
        auto const b = parm.b();
        auto const u = generate_canonical<RealType, minBits>(g);
        return a + u * (b - a);
    }

    friend constexpr auto operator==(uniform_real_distribution const& x, uniform_real_distribution const& y) -> bool
    {
        return x.param() == y.param();
    }

private:
    param_type param_;
};

} // namespace etl

#endif // TETL_RANDOM_UNIFORM_REAL_DISTRIBUTION_HPP
