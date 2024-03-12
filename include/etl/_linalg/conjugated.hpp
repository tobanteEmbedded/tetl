// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_CONJUGATED_HPP
#define TETL_LINALG_CONJUGATED_HPP

#include <etl/_linalg/accessor_conjugate.hpp>
#include <etl/_linalg/concepts.hpp>
#include <etl/_type_traits/is_arithmetic.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl::linalg {

template <typename ElementType, typename Extents, typename Layout, typename Accessor>
[[nodiscard]] constexpr auto conjugated(mdspan<ElementType, Extents, Layout, Accessor> a)
{
    if constexpr (is_arithmetic_v<remove_cv_t<ElementType>>) {
        return mdspan<ElementType, Extents, Layout, Accessor>{
            a.data_handle(),
            a.mapping(),
            a.accessor(),
        };
    } else {
        using element_type  = typename accessor_conjugate<Accessor>::element_type;
        using accessor_type = accessor_conjugate<Accessor>;

        return mdspan<element_type, Extents, Layout, accessor_type>{
            a.data_handle(),
            a.mapping(),
            accessor_type(a.accessor()),
        };
    }
}

template <typename ElementType, typename Extents, typename Layout, typename NestedAccessor>
[[nodiscard]] constexpr auto conjugated(mdspan<ElementType, Extents, Layout, accessor_conjugate<NestedAccessor>> a)
{
    using element_type  = typename NestedAccessor::element_type;
    using accessor_type = NestedAccessor;

    return mdspan<element_type, Extents, Layout, accessor_type>{
        a.data_handle(),
        a.mapping(),
        a.accessor().nested_accessor(),
    };
}

} // namespace etl::linalg

#endif // TETL_LINALG_CONJUGATED_HPP
