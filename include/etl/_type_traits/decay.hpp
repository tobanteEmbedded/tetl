// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_DECAY_HPP
#define TETL_TYPE_TRAITS_DECAY_HPP

#include <etl/_type_traits/add_pointer.hpp>
#include <etl/_type_traits/conditional.hpp>
#include <etl/_type_traits/is_array.hpp>
#include <etl/_type_traits/is_function.hpp>
#include <etl/_type_traits/remove_cv.hpp>
#include <etl/_type_traits/remove_extent.hpp>
#include <etl/_type_traits/remove_reference.hpp>

namespace etl {

/// Applies lvalue-to-rvalue, array-to-pointer, and function-to-pointer implicit
/// conversions to the type T, removes cv-qualifiers, and defines the resulting
/// type as the member typedef type.
template <typename T>
struct decay {
private:
    using U = remove_reference_t<T>;

public:
    using type = conditional_t<
        is_array_v<U>,
        remove_extent_t<U>*,
        conditional_t<is_function_v<U>, add_pointer_t<U>, remove_cv_t<U>>
    >;
};

template <typename T>
using decay_t = typename etl::decay<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_DECAY_HPP
