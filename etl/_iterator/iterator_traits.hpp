/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ITERATOR_ITERATOR_TRAITS_HPP
#define TETL_ITERATOR_ITERATOR_TRAITS_HPP

#include "etl/_cstddef/ptrdiff_t.hpp"
#include "etl/_iterator/tags.hpp"
#include "etl/_type_traits/remove_cv.hpp"

namespace etl {

/// \brief iterator_traits is the type trait class that provides uniform
/// interface to the properties of LegacyIterator types. This makes it possible
/// to implement algorithms only in terms of iterators.
///
/// \details The template can be specialized for user-defined iterators so that
/// the information about the iterator can be retrieved even if the type does
/// not provide the usual typedefs.
///
/// https://en.cppreference.com/w/cpp/iterator/iterator_traits
///
/// \group iterator_traits
/// \module Iterator
template <typename Iter>
struct iterator_traits;

/// \group iterator_traits
template <typename T>
struct iterator_traits<T*> {
    using iterator_concept  = contiguous_iterator_tag;
    using iterator_category = random_access_iterator_tag;
    using value_type        = remove_cv_t<T>;
    using difference_type   = ptrdiff_t;
    using pointer           = T*;
    using reference         = T&;
};

} // namespace etl

#endif // TETL_ITERATOR_ITERATOR_TRAITS_HPP