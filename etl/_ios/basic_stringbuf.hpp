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

#ifndef TETL_IOS_BASIC_STRINGBUF_HPP
#define TETL_IOS_BASIC_STRINGBUF_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_ios/basic_streambuf.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

template <typename CharT, size_t Capacity, typename Traits>
struct basic_stringbuf : basic_streambuf<CharT, Capacity, Traits,
                             basic_stringbuf<CharT, Capacity, Traits>> {
private:
    // The program is ill-formed if Traits::char_type is not CharT.
    static_assert(is_same_v<typename Traits::char_type, CharT>);

public:
    using char_type   = CharT;
    using traits_type = Traits;
    using int_type    = typename Traits::int_type;
    // using pos_type    = typename Traits::pos_type;
    // using off_type    = typename Traits::off_type;
};

} // namespace etl

#endif // TETL_IOS_BASIC_STRINGBUF_HPP