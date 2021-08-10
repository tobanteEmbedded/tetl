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

#ifndef TETL_TYPE_TRAITS_DECAY_HPP
#define TETL_TYPE_TRAITS_DECAY_HPP

#include "etl/_type_traits/add_pointer.hpp"
#include "etl/_type_traits/conditional.hpp"
#include "etl/_type_traits/is_array.hpp"
#include "etl/_type_traits/is_function.hpp"
#include "etl/_type_traits/remove_cv.hpp"
#include "etl/_type_traits/remove_extent.hpp"
#include "etl/_type_traits/remove_reference.hpp"

namespace etl {

/// Applies lvalue-to-rvalue, array-to-pointer, and function-to-pointer implicit
/// conversions to the type T, removes cv-qualifiers, and defines the resulting
/// type as the member typedef type.
template <typename T>
struct decay {
private:
    using U = remove_reference_t<T>;

public:
    using type = conditional_t<is_array_v<U>, remove_extent_t<U>*,
        conditional_t<is_function_v<U>, add_pointer_t<U>, remove_cv_t<U>>>;
};

template <typename T>
using decay_t = typename decay<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_DECAY_HPP