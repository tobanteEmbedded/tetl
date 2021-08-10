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

#ifndef TETL_ITERATOR_TAGS_HPP
#define TETL_ITERATOR_TAGS_HPP

namespace etl {

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct input_iterator_tag {
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct output_iterator_tag {
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct forward_iterator_tag : input_iterator_tag {
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct bidirectional_iterator_tag : forward_iterator_tag {
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct random_access_iterator_tag : bidirectional_iterator_tag {
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct contiguous_iterator_tag : random_access_iterator_tag {
};

} // namespace etl

#endif // TETL_ITERATOR_TAGS_HPP