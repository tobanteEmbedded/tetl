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

#undef NDEBUG

#include "etl/optional.hpp" // for optional
#include "etl/cassert.hpp"  // for TETL_ASSERT

auto main() -> int
{
    using etl::nullopt;
    using etl::optional;

    // construct default (implicit empty)
    auto opt0 = optional<short>();
    TETL_ASSERT(opt0.has_value() == false);
    TETL_ASSERT(static_cast<bool>(opt0) == false);

    // construct explicit empty
    auto opt1 = optional<int>(nullopt);
    TETL_ASSERT(opt1.has_value() == false);
    TETL_ASSERT(static_cast<bool>(opt1) == false);

    // construct explicit with value
    auto opt2 = optional<float>(42.0F);
    TETL_ASSERT(opt2.has_value());
    TETL_ASSERT(static_cast<bool>(opt2));

    // assign copy
    auto const opt3 = opt2;
    TETL_ASSERT(opt3.has_value());
    TETL_ASSERT(static_cast<bool>(opt3));

    // assign move
    auto const opt4 = move(opt2);
    TETL_ASSERT(opt4.has_value());
    TETL_ASSERT(static_cast<bool>(opt4));

    // value & value_or
    static_assert(optional<int>().value() == nullptr);
    static_assert(optional<int>().value_or(1) == 1);
    static_assert(*optional<int>(1).value() == 1);

    // reset
    auto opt5 = optional<float>(1.0F);
    TETL_ASSERT(opt5.has_value());
    opt5.reset();
    TETL_ASSERT(opt5.has_value() == false);

    return 0;
}
