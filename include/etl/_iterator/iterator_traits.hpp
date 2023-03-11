/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ITERATOR_ITERATOR_TRAITS_HPP
#define TETL_ITERATOR_ITERATOR_TRAITS_HPP

#include "etl/_cstddef/ptrdiff_t.hpp"
#include "etl/_iterator/tags.hpp"
#include "etl/_type_traits/remove_cv.hpp"
#include "etl/_type_traits/void_t.hpp"

namespace etl {

namespace detail {
template <typename Iter, typename = etl::void_t<>>
struct iterator_traits_impl { };

template <typename Iter>
struct iterator_traits_impl<Iter,
    etl::void_t<                          //
        typename Iter::iterator_category, //
        typename Iter::value_type,        //
        typename Iter::difference_type,   //
        typename Iter::pointer,           //
        typename Iter::reference          //
        >                                 //
    > {
    using iterator_category = typename Iter::iterator_category;
    using value_type        = typename Iter::value_type;
    using difference_type   = typename Iter::difference_type;
    using pointer           = typename Iter::pointer;
    using reference         = typename Iter::reference;
};

} // namespace detail

/// \brief iterator_traits is the type trait class that provides uniform
/// interface to the properties of LegacyIterator types. This makes it possible
/// to implement algorithms only in terms of iterators.
///
/// \details The template can be specialized for user-defined iterators so that
/// the information about the iterator can be retrieved even if the type does
/// not provide the usual typedefs.
///
/// https://en.cppreference.com/w/cpp/iterator/iterator_traits
template <typename Iter>
struct iterator_traits : detail::iterator_traits_impl<Iter> { };

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
