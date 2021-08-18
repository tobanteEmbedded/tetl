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

#ifndef TETL_IOS_BASIC_STREAMBUF_HPP
#define TETL_IOS_BASIC_STREAMBUF_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_ios/ios_base.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

template <typename CharT, size_t Capacity, typename Traits, typename Child>
struct basic_streambuf {
private:
    // The program is ill-formed if Traits::char_type is not CharT.
    static_assert(is_same_v<typename Traits::char_type, CharT>);

public:
    using char_type   = CharT;
    using traits_type = Traits;
    using int_type    = typename Traits::int_type;
    using off_type    = typename Traits::off_type;
    // using pos_type    = typename Traits::pos_type;

    auto pubsetbuf(char_type* str, streamsize n) -> basic_streambuf*
    {
        return self().setbuf(str, n);
    };

    // auto pubseekoff(off_type off, ios_base::seekdir dir,
    //     ios_base::openmode which = ios_base::in | ios_base::out) -> pos_type
    // {
    //     return self().seekoff(off, dir, which);
    // }

protected:
    auto setbuf(char_type* str, streamsize n) -> basic_streambuf*
    {
        ignore_unused(str, n);
        return *this;
    };

    // auto seekoff(off_type off, ios_base::seekdir dir,
    //     ios_base::openmode which = ios_base::in | ios_base::out) -> pos_type
    // {
    //     return pos_type(off_type(-1));
    // }

private:
    auto self() -> Child& { return static_cast<Child&>(*this); }
    auto self() const -> Child const&
    {
        return static_cast<Child const&>(*this);
    }
};

} // namespace etl

#endif // TETL_IOS_BASIC_STREAMBUF_HPP