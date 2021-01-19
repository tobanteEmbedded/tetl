/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_CONCEPTS_HPP
#define TAETL_CONCEPTS_HPP

#include "definitions.hpp"
#include "type_traits.hpp"

#if defined(TAETL_CPP_STANDARD_20) && defined(__cpp_concepts)
namespace etl
{
namespace detail
{
template <typename T, typename U>
concept same_helper = etl::is_same_v<T, U>;
}

template <typename T, typename U>
concept same_as = detail::same_helper<T, U>&& detail::same_helper<U, T>;

template <typename From, typename To>
concept convertible_to = etl::is_convertible_v<From, To>&& requires(
  etl::add_rvalue_reference_t<From> (&f)())
{
  static_cast<To>(f());
};

template <typename T>
concept integral = etl::is_integral_v<T>;

template <typename T>
concept signed_integral = etl::integral<T>&& etl::is_signed_v<T>;

template <typename T>
concept unsigned_integral = etl::integral<T>&& etl::is_unsigned_v<T>;

template <typename T>
concept floating_point = etl::is_floating_point_v<T>;

}  // namespace etl

#endif

#endif  // TAETL_CONCEPTS_HPP