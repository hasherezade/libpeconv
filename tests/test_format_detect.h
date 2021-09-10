#pragma once

#include <peconv.h>

namespace tests {

    // check if the supplied PE is in raw or virtual format
    int check_pe_format(const char *path);

}; //namespace tests
