// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_INDIRECTLY_READABLE_HPP
#define TETL_ITERATOR_INDIRECTLY_READABLE_HPP

#include <etl/_concepts/common_reference_with.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_iterator/iter_reference_t.hpp>
#include <etl/_iterator/iter_rvalue_reference_t.hpp>
#include <etl/_iterator/iter_value_t.hpp>
#include <etl/_iterator/ranges_iter_move.hpp>
#include <etl/_type_traits/remove_cvref.hpp>

namespace etl {

namespace detail {
template <typename In>
concept indirectly_readable_impl
    = etl::common_reference_with<etl::iter_reference_t<In>&&, etl::iter_value_t<In>&>
  and etl::common_reference_with<etl::iter_reference_t<In>&&, etl::iter_rvalue_reference_t<In>&&>
  and etl::common_reference_with<etl::iter_rvalue_reference_t<In>&&, etl::iter_value_t<In> const&>
  and requires(In const in) {
          typename etl::iter_value_t<In>;
          typename etl::iter_reference_t<In>;
          typename etl::iter_rvalue_reference_t<In>;
          { *in } -> etl::same_as<etl::iter_reference_t<In>>;
          { ranges::iter_move(in) } -> etl::same_as<etl::iter_rvalue_reference_t<In>>;
      };
} // namespace detail

template <typename In>
concept indirectly_readable = etl::detail::indirectly_readable_impl<etl::remove_cvref_t<In>>;

} // namespace etl

#endif // TETL_ITERATOR_INDIRECTLY_READABLE_HPP
