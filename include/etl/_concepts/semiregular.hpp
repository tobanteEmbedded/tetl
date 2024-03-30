// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_SEMIREGULAR_HPP
#define TETL_CONCEPTS_SEMIREGULAR_HPP

#include <etl/_concepts/copyable.hpp>
#include <etl/_concepts/default_initializable.hpp>

namespace etl {

/// \ingroup concepts
template <typename T>
concept semiregular = etl::copyable<T> and etl::default_initializable<T>;

} // namespace etl

#endif // TETL_CONCEPTS_SEMIREGULAR_HPP
