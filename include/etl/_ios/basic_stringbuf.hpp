// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_IOS_BASIC_STRINGBUF_HPP
#define TETL_IOS_BASIC_STRINGBUF_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_ios/basic_streambuf.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl {

template <typename CharT, size_t Capacity, typename Traits>
struct basic_stringbuf : basic_streambuf<CharT, Capacity, Traits, basic_stringbuf<CharT, Capacity, Traits>> {
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
