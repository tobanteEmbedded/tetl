// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_BLAS1_ADD_HPP
#define TETL_LINALG_BLAS1_ADD_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_linalg/concepts.hpp>
#include <etl/_utility/cmp_less.hpp>

namespace etl::linalg {

/// \ingroup linalg
template <in_object InObj1, in_object InObj2, out_object OutObj>
    requires(InObj1::rank() == OutObj::rank() and InObj2::rank() == OutObj::rank())
constexpr auto add(InObj1 x, InObj2 y, OutObj z) -> void
{
    TETL_PRECONDITION(x.extents() == y.extents());

    using size_type = detail::common_size_type_t<InObj1, InObj2, OutObj>;

    if constexpr (OutObj::rank() == 1) {
        for (size_type row{0}; etl::cmp_less(row, x.extent(0)); ++row) {
            z(row) = x(row) + y(row);
        }
    } else {
        static_assert(OutObj::rank() == 2);
        for (size_type row{0}; etl::cmp_less(row, x.extent(0)); ++row) {
            for (size_type col{0}; etl::cmp_less(col, x.extent(1)); ++col) {
                z(row, col) = x(row, col) + y(row, col);
            }
        }
    }
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_ADD_HPP
