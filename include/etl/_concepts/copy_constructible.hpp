// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_COPY_CONSTRUCTIBLE_HPP
#define TETL_CONCEPTS_COPY_CONSTRUCTIBLE_HPP

#include "etl/_concepts/constructible_from.hpp"
#include "etl/_concepts/convertible_to.hpp"
#include "etl/_concepts/move_constructible.hpp"

namespace etl {

/// \brief The concept copy_constructible is satisfied if T is an lvalue
/// reference type, or if it is a move_constructible object type where an object
/// of that type can constructed from a (possibly const) lvalue or const rvalue
/// of that type in both direct- and copy-initialization contexts with the usual
/// semantics (a copy is constructed with the source unchanged).
// clang-format off
template <typename T>
concept copy_constructible =
  move_constructible<T> and
  constructible_from<T, T&> and convertible_to<T&, T> and
  constructible_from<T, const T&> and convertible_to<const T&, T> and
  constructible_from<T, const T> and convertible_to<const T, T>;
// clang-format on

} // namespace etl

#endif // TETL_CONCEPTS_COPY_CONSTRUCTIBLE_HPP
