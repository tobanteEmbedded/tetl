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

#include "etl/memory.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("memory/small_ptr: construct", "[memory]", int, float, long)
{
    using Ptr = etl::small_ptr<TestType, 0, uint64_t>;
    auto ptr  = Ptr {nullptr};
    REQUIRE(ptr.compressed_value() == 0);
}

TEMPLATE_TEST_CASE("memory/small_ptr: size", "[memory]", uint8_t, uint16_t,
                   uint32_t, uint64_t)
{
    using Ptr = etl::small_ptr<int, 0, TestType>;
    auto ptr  = Ptr {nullptr};
    STATIC_REQUIRE(sizeof(ptr) == sizeof(TestType));
}

namespace
{
struct SomeStruct
{
    float x, y;
    int a, b;
};

}  // namespace
TEMPLATE_TEST_CASE("memory/small_ptr: offset", "[memory]", int, float, long,
                   SomeStruct)
{
    using namespace Catch::Generators;
    using ptr_t = etl::small_ptr<TestType const, 16, uint16_t>;
    auto [addr] = GENERATE(table<int>({
        {32},
        {2048},
        {4100},
    }));
    auto ptr    = ptr_t {reinterpret_cast<TestType*>(addr)};
    REQUIRE(ptr.compressed_value() == addr - 16);
    REQUIRE(reinterpret_cast<intptr_t>(ptr.operator->())
            == static_cast<intptr_t>(addr));
}
