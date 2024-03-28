// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_INDIRECTLY_REGULAR_UNARY_INVOCABLE_HPP
#define TETL_ITERATOR_INDIRECTLY_REGULAR_UNARY_INVOCABLE_HPP

#include <etl/_concepts/common_reference_with.hpp>
#include <etl/_concepts/copy_constructible.hpp>
#include <etl/_concepts/regular_invocable.hpp>
#include <etl/_iterator/indirectly_readable.hpp>
#include <etl/_iterator/iter_common_reference_t.hpp>
#include <etl/_iterator/iter_reference_t.hpp>
#include <etl/_iterator/iter_value_t.hpp>
#include <etl/_type_traits/invoke_result.hpp>

namespace etl {

// clang-format off
template<typename F,typename I >
concept indirectly_regular_unary_invocable =
        etl::indirectly_readable<I>
    and etl::copy_constructible<F>
    and etl::regular_invocable<F&, etl::iter_value_t<I>&>
    and etl::regular_invocable<F&, etl::iter_reference_t<I>>
    and etl::regular_invocable<F&, etl::iter_common_reference_t<I>>
    and etl::common_reference_with<etl::invoke_result_t<F&, etl::iter_value_t<I>&>, etl::invoke_result_t<F&, etl::iter_reference_t<I>>>;
// clang-format on

} // namespace etl

#endif // TETL_ITERATOR_INDIRECTLY_REGULAR_UNARY_INVOCABLE_HPP
