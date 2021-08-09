// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_DETAIL_ITERATOR_ITERATOR_TRAITS_HPP
#define TETL_DETAIL_ITERATOR_ITERATOR_TRAITS_HPP

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
/// \notes
/// [cppreference.com/w/cpp/iterator/iterator_traits](https://en.cppreference.com/w/cpp/iterator/iterator_traits)
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

#endif // TETL_DETAIL_ITERATOR_ITERATOR_TRAITS_HPP