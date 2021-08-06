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

#define TETL_RTOS_USE_STUBS
#include "etl/experimental/rtos/stream_buffer.hpp"

#include "catch2/catch_template_test_macros.hpp"

namespace rtos = etl::experimental::rtos;
namespace net  = etl::experimental::net;

TEST_CASE("experimental/rtos/stream_buffer: ", "[experimental][rtos]")
{
    auto sb = rtos::stream_buffer { 128, 1 };
    REQUIRE(sb.empty() == false);
    REQUIRE(sb.full() == false);
    REQUIRE(sb.bytes_available() == 0);
    REQUIRE(sb.space_available() == 0);

    auto read = etl::array<unsigned char, 16> {};
    REQUIRE(sb.read(net::make_buffer(read), 0) == 0);
    REQUIRE(sb.read_from_isr(net::make_buffer(read), 0) == 0);

    auto const write = etl::array<unsigned char, 16> {};
    REQUIRE(sb.write(net::make_buffer(write), 0) == 0);
    REQUIRE(sb.write_from_isr(net::make_buffer(write), 0) == 0);
}