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

#ifndef TAETL_VERSION_HPP
#define TAETL_VERSION_HPP

#define TAETL_REVISION_MAJOR 0
#define TAETL_REVISION_MINOR 2
#define TAETL_REVISION_PATCH 0
#define TAETL_REVISION_STRING "0.2.0"

namespace etl
{
enum class LanugageStandard
{
    Cpp98 = 199711L,
    Cpp11 = 201103L,
    Cpp14 = 201402L,
    Cpp17 = 201703L,
    Cpp20 = 201704L,  // Todo: Replace with actual standard macro value
};

#if __cplusplus < 201703L
#error "C++17 or newer is required"
#endif

#if __cplusplus == 201703L
constexpr auto kLanguageStandard = LanugageStandard::Cpp17;
#endif

#if __cplusplus > 201703L
constexpr auto kLanguageStandard = LanugageStandard::Cpp20;
#endif
}  // namespace etl

#endif  // TAETL_VERSION_HPP