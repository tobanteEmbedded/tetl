// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_DEFAULT_INITIALIZABLE_HPP
#define TETL_CONCEPTS_DEFAULT_INITIALIZABLE_HPP

#include "etl/_concepts/constructible_from.hpp"
#include "etl/_new/operator.hpp"

#if defined(__cpp_concepts)
namespace etl {

/// \brief The default_initializable concept checks whether variables of type T
/// can be value-initialized (T() is well-formed); direct-list-initialized from
/// an empty initializer list (T{} is well-formed); and default-initialized (T
/// t; is well-formed). Access checking is performed as if in a context
/// unrelated to T. Only the validity of the immediate context of the variable
/// initialization is considered.
// clang-format off
template <typename T>
concept default_initializable =
  constructible_from<T> &&
  requires { T {}; } &&
  requires { ::new (static_cast<void*>(nullptr)) T; };
// clang-format on

} // namespace etl
#endif

#endif // TETL_CONCEPTS_DEFAULT_INITIALIZABLE_HPP
