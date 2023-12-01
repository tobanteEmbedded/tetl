// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_SCALED_SCALAR_HPP
#define TETL_LINALG_SCALED_SCALAR_HPP

#include <etl/_linalg/proxy_reference.hpp>
#include <etl/_type_traits/declval.hpp>

namespace etl::linalg::detail {

template <typename ScalingFactor, typename ReferenceValue>
concept scalable = requires { declval<ScalingFactor>() * declval<ReferenceValue>(); };

template <typename ScalingFactor, typename Reference, typename ReferenceValue>
    requires(scalable<ScalingFactor, ReferenceValue>)
struct scaled_scalar
    : proxy_reference<Reference, ReferenceValue, scaled_scalar<ScalingFactor, Reference, ReferenceValue>> {
    using value_type = decltype(declval<ScalingFactor>() * ReferenceValue(declval<Reference>()));

    constexpr explicit scaled_scalar(ScalingFactor const& scalingFactor, Reference const& reference)
        : proxy_reference<Reference, ReferenceValue,
            scaled_scalar<ScalingFactor, Reference, ReferenceValue>> { reference }
        , _scalingFactor { scalingFactor }
    {
    }

    [[nodiscard]] constexpr auto to_value(Reference reference) const -> value_type
    {
        return _scalingFactor * ReferenceValue(reference);
    }

private:
    ScalingFactor _scalingFactor;
};

} // namespace etl::linalg::detail

#endif // TETL_LINALG_SCALED_SCALAR_HPP
