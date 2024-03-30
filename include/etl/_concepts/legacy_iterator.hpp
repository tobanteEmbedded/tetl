// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_LEGACY_ITERATOR_HPP
#define TETL_CONCEPTS_LEGACY_ITERATOR_HPP

#include <etl/_concepts/copyable.hpp>
#include <etl/_concepts/referenceable.hpp>
#include <etl/_concepts/same_as.hpp>

namespace etl {

/// \note Non-standard extension
/// \headerfile etl/concepts.hpp
/// \ingroup concepts
template <typename Iter>
concept legacy_iterator = requires(Iter i) {
    { *i } -> etl::referenceable;
    { ++i } -> etl::same_as<Iter&>;
    { *i++ } -> etl::referenceable;
} and etl::copyable<Iter>;

} // namespace etl

#endif // TETL_CONCEPTS_LEGACY_ITERATOR_HPP
