/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_RANDOM_UNIFORM_REAL_DISTRIBUTION_HPP
#define TETL_RANDOM_UNIFORM_REAL_DISTRIBUTION_HPP

#include <etl/_limits/numeric_limits.hpp>
#include <etl/_random/generate_canonical.hpp>
#include <etl/_utility/pair.hpp>

namespace etl {

template <typename RealType = double>
struct uniform_real_distribution {
    using result_type = RealType;
    using param_type  = etl::pair<RealType, RealType>;

    constexpr uniform_real_distribution() : uniform_real_distribution { static_cast<RealType>(0) } { }

    explicit constexpr uniform_real_distribution(param_type const& parm) : param_ { parm } { }

    explicit constexpr uniform_real_distribution(RealType a, RealType b = 1.0)
        : uniform_real_distribution { param_type { a, b } }
    {
    }

    constexpr auto param(param_type const& parm) -> void { param_ = parm; }
    [[nodiscard]] constexpr auto param() const -> param_type { return param_; }

    [[nodiscard]] constexpr auto a() const -> result_type { return etl::get<0>(param_); }
    [[nodiscard]] constexpr auto b() const -> result_type { return etl::get<1>(param_); }

    [[nodiscard]] constexpr auto min() const -> result_type { return a(); }
    [[nodiscard]] constexpr auto max() const -> result_type { return b(); }

    constexpr auto reset() -> void { (void)this; }

    template <typename URBG>
    [[nodiscard]] constexpr auto operator()(URBG& g) -> result_type
    {
        return (*this)(g, param_);
    }

    template <typename URBG>
    [[nodiscard]] constexpr auto operator()(URBG& g, param_type const& parm) -> result_type
    {
        constexpr auto digits  = static_cast<size_t>(numeric_limits<RealType>::digits);
        constexpr auto bits    = ~size_t { 0 };
        constexpr auto minBits = digits < bits ? digits : bits;
        static_assert(minBits <= 64);

        // x = a + u * (b - a)
        auto const a = etl::get<0>(parm);
        auto const b = etl::get<1>(parm);
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
