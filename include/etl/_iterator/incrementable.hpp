// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_INCREMENTABLE_HPP
#define TETL_ITERATOR_INCREMENTABLE_HPP

#include <etl/_concepts/regular.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_iterator/weakly_incrementable.hpp>

namespace etl {

template <typename T>
concept incrementable = etl::regular<T> and etl::weakly_incrementable<T> and requires(T i) {
    { i++ } -> etl::same_as<T>;
};

} // namespace etl

#endif // TETL_ITERATOR_INCREMENTABLE_HPP
