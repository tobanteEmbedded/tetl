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

#include "catch2/catch_template_test_macros.hpp"

#include "etl/array.hpp"
#include "etl/cstring.hpp"
#include "etl/string_view.hpp"

TEST_CASE("cstring: strcpy", "[cstring]")
{
  char source[32] = {"test"};
  char dest[32] {};

  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
  etl::strcpy(dest, source);

  CHECK(etl::strlen(dest) == 4);
}

TEST_CASE("cstring: strncpy", "[cstring]")
{
  char source[32] = {"test"};
  char dest[32] {};
  etl::strncpy(dest, source, 2);
  CHECK(dest[0] == 't');
  CHECK(dest[1] == 'e');
}

TEST_CASE("cstring: strcat", "[cstring]")
{
  char str[50]  = "Hello ";
  char str2[50] = "World!";

  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
  etl::strcat(str, str2);
  CHECK(etl::string_view {str} == etl::string_view {"Hello World!"});

  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
  etl::strcat(str, " Goodbye World!");
  CHECK(etl::string_view {str}
        == etl::string_view {"Hello World! Goodbye World!"});
}

TEST_CASE("cstring: strncat", "[cstring]")
{
  char str[50]  = "Hello ";
  char str2[50] = "World!";

  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
  etl::strcat(str, str2);
  CHECK(etl::string_view {str} == etl::string_view {"Hello World!"});
  etl::strncat(str, " Goodbye World!", 3);
  CHECK(etl::string_view {str} == etl::string_view {"Hello World! Go"});
}

TEST_CASE("cstring: strncmp", "[cstring]")
{
  CHECK(etl::strncmp("Hello, world!", "Hello, everybody!", 13) > 0);
  CHECK(etl::strncmp("Hello, everybody!", "Hello, world!", 13) < 0);
  CHECK(etl::strncmp("Hello, everybody!", "Hello, world!", 7) == 0);
}

TEST_CASE("cstring: memcpy", "[cstring]")
{
  auto source = etl::array<etl::uint8_t, 2> {};
  source[0]   = 1;
  source[1]   = 2;
  REQUIRE(source.at(0) == 1);
  REQUIRE(source.at(1) == 2);

  auto destination = etl::array<etl::uint8_t, 2> {};
  REQUIRE(destination.at(0) == 0);
  REQUIRE(destination.at(1) == 0);

  etl::memcpy(destination.data(), source.data(), source.size());
  REQUIRE(source.at(0) == 1);
  REQUIRE(source.at(1) == 2);
  REQUIRE(destination.at(0) == 1);
  REQUIRE(destination.at(1) == 2);
}

TEST_CASE("cstring: memset", "[cstring]")
{
  auto buffer = etl::array<etl::uint8_t, 2> {};
  REQUIRE(buffer.at(0) == 0);
  REQUIRE(buffer.at(1) == 0);

  etl::memset(buffer.data(), 1, buffer.size());
  REQUIRE(buffer.at(0) == 1);
  REQUIRE(buffer.at(1) == 1);
}

TEST_CASE("cstring: strlen", "[cstring]")
{
  REQUIRE(etl::strlen("") == 0);
  REQUIRE(etl::strlen("a") == 1);
  REQUIRE(etl::strlen("to") == 2);
  REQUIRE(etl::strlen("xxxxxxxxxx") == 10);
}
