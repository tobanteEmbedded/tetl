// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_DEREFERENCEABLE_HPP
#define TETL_ITERATOR_DEREFERENCEABLE_HPP

#include <etl/_iterator/can_reference.hpp>

namespace etl::detail {

// clang-format off
template <typename T>
concept dereferenceable = requires(T& t) {
  { *t } -> can_reference;
};
// clang-format on

} // namespace etl::detail

#endif // TETL_ITERATOR_DEREFERENCEABLE_HPP
