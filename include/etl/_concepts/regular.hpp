// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_REGULAR_HPP
#define TETL_CONCEPTS_REGULAR_HPP

#include <etl/_concepts/equality_comparable.hpp>
#include <etl/_concepts/semiregular.hpp>

namespace etl {

/// \ingroup concepts
template <typename T>
concept regular = etl::semiregular<T> and etl::equality_comparable<T>;

} // namespace etl

#endif // TETL_CONCEPTS_REGULAR_HPP
