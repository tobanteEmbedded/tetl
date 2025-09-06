// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CONCEPTS_COMMON_REFERENCE_WITH_HPP
#define TETL_CONCEPTS_COMMON_REFERENCE_WITH_HPP

#include <etl/_concepts/convertible_to.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/common_reference.hpp>

namespace etl {

/// \ingroup concepts
template <typename T, typename U>
concept common_reference_with = same_as<common_reference_t<T, U>, common_reference_t<U, T>>
                            and convertible_to<T, common_reference_t<T, U>>
                            and convertible_to<U, common_reference_t<T, U>>;

} // namespace etl

#endif // TETL_CONCEPTS_COMMON_REFERENCE_WITH_HPP
