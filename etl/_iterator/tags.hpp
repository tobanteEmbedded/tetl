/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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