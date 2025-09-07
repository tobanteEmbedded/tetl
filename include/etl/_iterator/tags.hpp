// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_ITERATOR_TAGS_HPP
#define TETL_ITERATOR_TAGS_HPP

namespace etl {

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \ingroup iterator
struct input_iterator_tag { };

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \ingroup iterator
struct output_iterator_tag { };

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \ingroup iterator
struct forward_iterator_tag : input_iterator_tag { };

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \ingroup iterator
struct bidirectional_iterator_tag : forward_iterator_tag { };

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \ingroup iterator
struct random_access_iterator_tag : bidirectional_iterator_tag { };

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \ingroup iterator
struct contiguous_iterator_tag : random_access_iterator_tag { };

} // namespace etl

#endif // TETL_ITERATOR_TAGS_HPP
