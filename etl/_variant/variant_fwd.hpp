/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_VARIANT_VARIANT_FWD_HPP
#define TETL_VARIANT_VARIANT_FWD_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/add_pointer.hpp"

namespace etl {

template <typename... Types>
struct variant;

template <typename T>
struct variant_size;

/// \brief Provides compile-time indexed access to the types of the alternatives
/// of the possibly cv-qualified variant, combining cv-qualifications of the
/// variant (if any) with the cv-qualifications of the alternative.
template <etl::size_t I, typename T>
struct variant_alternative;

template <etl::size_t I, typename... Types>
constexpr auto get_if(etl::variant<Types...>* v) noexcept
    -> etl::add_pointer_t<typename etl::variant_alternative<I,
        etl::variant<Types...>>::type>; // NOLINT

} // namespace etl

#endif // TETL_VARIANT_VARIANT_FWD_HPP