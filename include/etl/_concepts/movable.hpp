// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_MOVABLE_HPP
#define TETL_CONCEPTS_MOVABLE_HPP

#include <etl/_concepts/assignable_from.hpp>
#include <etl/_concepts/move_constructible.hpp>
#include <etl/_concepts/swappable.hpp>
#include <etl/_type_traits/is_object.hpp>

namespace etl {

template <typename T>
concept movable = is_object_v<T> and move_constructible<T> and assignable_from<T&, T> and swappable<T>;

} // namespace etl

#endif // TETL_CONCEPTS_MOVABLE_HPP
