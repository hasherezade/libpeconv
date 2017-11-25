#pragma once

#include "peconv.h"
#include "file_helper.h"

namespace tests {

    // Get the path of the current module and loads it by the custom loader. Then, deploys the module and checks if it runs properly.
    int deploy_self();

    int deploy_self_ex(peconv::t_function_resolver func_resolver);

}; //namespace tests
