// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_ACCESSOR_CONJUGATE_HPP
#define TETL_LINALG_ACCESSOR_CONJUGATE_HPP

#include <etl/_linalg/conjugated_scalar.hpp>
#include <etl/_type_traits/add_const.hpp>
#include <etl/_type_traits/conditional.hpp>
#include <etl/_type_traits/is_arithmetic.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl::linalg {

template <typename Accessor>
struct accessor_conjugate {
    using reference
        = conditional_t<is_arithmetic_v<remove_cv_t<typename Accessor::element_type>>, typename Accessor::reference,
            detail::conjugated_scalar<typename Accessor::reference, remove_cv_t<typename Accessor::element_type>>>;
    using element_type     = add_const_t<conditional_t<is_arithmetic_v<remove_cv_t<typename Accessor::element_type>>,
        typename Accessor::element_type, typename reference::value_type>>;
    using data_handle_type = typename Accessor::data_handle_type;
    using offset_policy    = conditional_t<is_arithmetic_v<remove_cv_t<typename Accessor::element_type>>,
        typename Accessor::offset_policy, accessor_conjugate<typename Accessor::offset_policy>>;

    constexpr accessor_conjugate(Accessor a) : nestedAccessor_(a) { }

    [[nodiscard]] constexpr auto access(data_handle_type p, size_t i) const
        noexcept(noexcept(reference(nestedAccessor_.access(p, i)))) -> reference
    {
        return reference(nestedAccessor_.access(p, i));
    }

    [[nodiscard]] constexpr auto offset(data_handle_type p, size_t i) const
        noexcept(noexcept(nestedAccessor_.offset(p, i))) -> typename offset_policy::data_handle_type
    {
        nestedAccessor_.offset(p, i);
    }

    [[nodiscard]] constexpr auto nested_accessor() const -> Accessor { return nestedAccessor_; }

private:
    Accessor nestedAccessor_;
};

} // namespace etl::linalg

#endif // TETL_LINALG_ACCESSOR_CONJUGATE_HPP
