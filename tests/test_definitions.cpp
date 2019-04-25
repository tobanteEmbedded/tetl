#include <assert.h>

// TAETL
#include "taetl/definitions.h"

int main()
{
    assert(sizeof(taetl::size_t) == sizeof(size_t));
    return 0;
}