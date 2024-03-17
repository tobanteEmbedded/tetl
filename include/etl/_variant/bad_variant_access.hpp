// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_BAD_VARIANT_ACCESS_HPP
#define TETL_VARIANT_BAD_VARIANT_ACCESS_HPP

#include <etl/_exception/exception.hpp>

namespace etl {

/// \brief etl::bad_variant_access is the type of the exception thrown in the
/// following situations: (1) etl::get(etl::variant) called with an index or
/// type that does not match the currently active alternative. (2) etl::visit
/// called to visit a variant that is valueless_by_exception
struct bad_variant_access : exception {
    constexpr bad_variant_access() = default;

    constexpr explicit bad_variant_access(char const* what) : exception{what} { }
};

} // namespace etl

#endif // TETL_VARIANT_BAD_VARIANT_ACCESS_HPP
