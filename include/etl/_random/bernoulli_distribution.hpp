// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANDOM_BERNOULLI_DISTRIBUTION_HPP
#define TETL_RANDOM_BERNOULLI_DISTRIBUTION_HPP

#include <etl/_limits/numeric_limits.hpp>
#include <etl/_random/generate_canonical.hpp>
#include <etl/_tuple/tuple.hpp>

namespace etl {

/// \ingroup random
struct bernoulli_distribution {
    using result_type = bool;

    struct param_type {
        using distribution_type = bernoulli_distribution;

        constexpr param_type() noexcept
            : param_type{0.5}
        {
        }

        explicit constexpr param_type(double p) noexcept
            : probability{p}
        {
        }

        [[nodiscard]] constexpr auto p() const noexcept -> double { return probability; }

        [[nodiscard]] friend constexpr auto operator==(param_type const& lhs, param_type const& rhs) noexcept -> bool
        {
            return lhs.probability == rhs.probability;
        }

        double probability;
    };

    constexpr bernoulli_distribution() noexcept
        : bernoulli_distribution{0.5}
    {
    }

    explicit constexpr bernoulli_distribution(double p) noexcept
        : bernoulli_distribution{param_type{p}}
    {
    }

    explicit constexpr bernoulli_distribution(param_type const& parm) noexcept
        : _param{parm}
    {
    }

    [[nodiscard]] constexpr auto p() const noexcept -> double { return _param.p(); }

    constexpr auto param(param_type const& parm) noexcept -> void { _param = parm; }

    [[nodiscard]] constexpr auto param() const noexcept -> param_type { return _param; }

    [[nodiscard]] constexpr auto min() const noexcept -> result_type
    {
        (void)this;
        return false;
    }

    [[nodiscard]] constexpr auto max() const noexcept -> result_type
    {
        (void)this;
        return true;
    }

    constexpr auto reset() noexcept -> void { (void)this; }

    template <typename URBG>
    [[nodiscard]] constexpr auto operator()(URBG& g) noexcept(noexcept(g())) -> result_type
    {
        return (*this)(g, _param);
    }

    template <typename URBG>
    [[nodiscard]] constexpr auto operator()(URBG& g, param_type const& parm) noexcept(noexcept(g())) -> result_type
    {
        constexpr auto digits  = static_cast<size_t>(numeric_limits<double>::digits);
        constexpr auto bits    = ~size_t{0};
        constexpr auto minBits = digits < bits ? digits : bits;
        static_assert(minBits <= 64);

        return generate_canonical<double, minBits>(g) < parm.p();
    }

    [[nodiscard]] friend constexpr auto
    operator==(bernoulli_distribution const& x, bernoulli_distribution const& y) noexcept -> bool
    {
        return x.param() == y.param();
    }

private:
    param_type _param;
};

} // namespace etl

#endif // TETL_RANDOM_BERNOULLI_DISTRIBUTION_HPP
