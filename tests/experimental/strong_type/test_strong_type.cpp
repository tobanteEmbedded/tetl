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

// TAETL
#include "etl/experimental/strong_type/strong_type.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("experimental/strong_type: type_traits", "[experimental]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
    using namespace etl::experimental;

    using Kilogram = strong_type<TestType, struct Kilogram_tag>;

    static_assert(sizeof(Kilogram) == sizeof(typename Kilogram::value_type));

    static_assert(std::is_constructible_v<Kilogram>);
    static_assert(std::is_trivially_constructible_v<Kilogram>);
    static_assert(std::is_nothrow_constructible_v<Kilogram>);

    static_assert(std::is_destructible_v<Kilogram>);
    static_assert(std::is_trivially_destructible_v<Kilogram>);
    static_assert(std::is_nothrow_destructible_v<Kilogram>);

    static_assert(std::is_assignable_v<Kilogram, Kilogram>);
    static_assert(std::is_trivially_assignable_v<Kilogram, Kilogram>);
    static_assert(std::is_nothrow_assignable_v<Kilogram, Kilogram>);

    static_assert(std::is_copy_constructible_v<Kilogram>);
    static_assert(std::is_trivially_copy_constructible_v<Kilogram>);
    static_assert(std::is_nothrow_copy_constructible_v<Kilogram>);

    static_assert(std::is_copy_assignable_v<Kilogram>);
    static_assert(std::is_trivially_copy_assignable_v<Kilogram>);
    static_assert(std::is_nothrow_copy_assignable_v<Kilogram>);

    static_assert(std::is_move_constructible_v<Kilogram>);
    static_assert(std::is_trivially_move_constructible_v<Kilogram>);
    static_assert(std::is_nothrow_move_constructible_v<Kilogram>);

    static_assert(std::is_move_assignable_v<Kilogram>);
    static_assert(std::is_trivially_move_assignable_v<Kilogram>);
    static_assert(std::is_nothrow_move_assignable_v<Kilogram>);

    static_assert(std::is_swappable_v<Kilogram>);
    static_assert(std::is_nothrow_swappable_v<Kilogram>);

    static_assert(std::is_trivial_v<Kilogram>);

    static_assert(!std::has_virtual_destructor_v<Kilogram>);
}