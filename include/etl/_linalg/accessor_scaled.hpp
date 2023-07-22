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
    using data_handle_type = Accessor::data_handle_type;
    using offset_policy    = accessor_scaled<ScalingFactor, typename Accessor::offset_policy>;

    constexpr accessor_scaled(ScalingFactor const& s, Accessor const& a) : scaling_factor_ { s }, nested_accessor_ { a }
    {
    }

    [[nodiscard]] constexpr auto access(data_handle_type p, size_t i) const noexcept -> reference
    {
        return reference(scaling_factor_, nested_accessor_.access(p, i));
    }

    [[nodiscard]] constexpr auto offset(data_handle_type p, size_t i) const noexcept -> offset_policy::data_handle_type
    {
        return nested_accessor_.offset(p, i);
    }

    [[nodiscard]] constexpr auto scaling_factor() const -> ScalingFactor { return scaling_factor_; }

    [[nodiscard]] constexpr auto nested_accessor() const -> Accessor { return nested_accessor_; }

private:
    ScalingFactor scaling_factor_;
    Accessor nested_accessor_;
};

} // namespace etl::linalg

#endif // TETL_LINALG_ACCESSOR_SCALED_HPP
