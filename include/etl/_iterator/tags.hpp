// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_TAGS_HPP
#define TETL_ITERATOR_TAGS_HPP

namespace etl {

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct input_iterator_tag { };

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct output_iterator_tag { };

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct forward_iterator_tag : input_iterator_tag { };

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct bidirectional_iterator_tag : forward_iterator_tag { };

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct random_access_iterator_tag : bidirectional_iterator_tag { };

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct contiguous_iterator_tag : random_access_iterator_tag { };

} // namespace etl

#endif // TETL_ITERATOR_TAGS_HPP
