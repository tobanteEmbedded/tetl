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

#include <assert.h>  // for assert
#include <stdio.h>   // for printf

#include "etl/set.hpp"  // for static_set

auto main() -> int
{
    etl::static_set<double, 16> set;
    set.insert(3.0);  // 3.0
    set.insert(1.0);  // 1.0, 3.0
    set.insert(2.0);  // 1.0, 2.0, 3.0
    set.insert(4.0);  // 1.0, 2.0, 3.0, 4.0
    set.insert(4.0);  // 1.0, 2.0, 3.0, 4.0

    for (auto key : set) { printf("%f\n", key); }

    assert(set.contains(2.0));
    assert(set.contains(5.0) == false);

    return 0;
}
