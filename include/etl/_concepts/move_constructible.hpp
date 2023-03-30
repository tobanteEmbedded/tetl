// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_MOVE_CONSTRUCTIBLE_HPP
#define TETL_CONCEPTS_MOVE_CONSTRUCTIBLE_HPP

#include "etl/_concepts/constructible_from.hpp"
#include "etl/_concepts/convertible_to.hpp"

#if defined(__cpp_concepts)
namespace etl {

/// \brief The concept move_constructible is satisfied if T is a reference type,
/// or if it is an object type where an object of that type can be constructed
/// from an rvalue of that type in both direct- and copy-initialization
/// contexts, with the usual semantics.
///
/// https://en.cppreference.com/w/cpp/concepts/move_constructible
template <typename T>
concept move_constructible = constructible_from<T, T> && convertible_to<T, T>;

} // namespace etl
#endif

#endif // TETL_CONCEPTS_MOVE_CONSTRUCTIBLE_HPP
