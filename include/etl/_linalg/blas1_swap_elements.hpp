// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_BLAS1_SWAP_ELEMENTS_HPP
#define TETL_LINALG_BLAS1_SWAP_ELEMENTS_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_linalg/concepts.hpp>
#include <etl/_utility/cmp_less.hpp>
#include <etl/_utility/swap.hpp>

namespace etl::linalg {

/// \ingroup linalg
template <inout_object InOutObj1, inout_object InOutObj2>
    requires(InOutObj1::rank() == InOutObj1::rank())
constexpr auto swap_elements(InOutObj1 x, InOutObj2 y) -> void
{
    TETL_PRECONDITION(x.extents() == y.extents());

    using size_type = detail::common_size_type_t<InOutObj1, InOutObj2>;

    if constexpr (InOutObj1::rank() == 1) {
        for (size_type i{0}; etl::cmp_less(i, x.extent(0)); ++i) {
            using etl::swap;
            swap(x(i), y(i));
        }
    } else {
        static_assert(InOutObj1::rank() == 2);
        for (size_type i{0}; etl::cmp_less(i, x.extent(0)); ++i) {
            for (size_type j{0}; etl::cmp_less(j, x.extent(1)); ++j) {
                using etl::swap;
                swap(x(i, j), y(i, j));
            }
        }
    }
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_SWAP_ELEMENTS_HPP
