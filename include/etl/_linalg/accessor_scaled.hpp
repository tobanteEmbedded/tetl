// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_ACCESSOR_SCALED_HPP
#define TETL_LINALG_ACCESSOR_SCALED_HPP

#include <etl/_linalg/scaled_scalar.hpp>
#include <etl/_type_traits/add_const.hpp>
#include <etl/_type_traits/is_copy_constructible.hpp>

namespace etl::linalg {

template <typename ScalingFactor, typename Accessor>
    requires(is_copy_constructible_v<typename Accessor::reference>)
struct accessor_scaled {
    using reference
        = detail::scaled_scalar<ScalingFactor, typename Accessor::reference, typename Accessor::element_type>;
    using element_type     = add_const_t<typename reference::value_type>;
    using data_handle_type = typename Accessor::data_handle_type;
    using offset_policy    = accessor_scaled<ScalingFactor, typename Accessor::offset_policy>;

    constexpr accessor_scaled(ScalingFactor const& s, Accessor const& a) : _scalingFactor { s }, _nestedAccessor { a }
    {
    }

    [[nodiscard]] constexpr auto access(data_handle_type p, size_t i) const noexcept -> reference
    {
        return reference(_scalingFactor, _nestedAccessor.access(p, i));
    }

    [[nodiscard]] constexpr auto offset(data_handle_type p, size_t i) const noexcept ->
        typename offset_policy::data_handle_type
    {
        return _nestedAccessor.offset(p, i);
    }

    [[nodiscard]] constexpr auto scaling_factor() const -> ScalingFactor { return _scalingFactor; }

    [[nodiscard]] constexpr auto nested_accessor() const -> Accessor { return _nestedAccessor; }

private:
    ScalingFactor _scalingFactor;
    Accessor _nestedAccessor;
};

} // namespace etl::linalg

#endif // TETL_LINALG_ACCESSOR_SCALED_HPP
