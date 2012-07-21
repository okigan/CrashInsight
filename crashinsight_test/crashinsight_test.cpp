// crashinsight_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define BOOST_TEST_MODULE MyTest
#include <boost/test/unit_test.hpp>

#include <boost/assign.hpp>
#include <boost/any.hpp>

#include "../crashinsightlib/crashinsight.h"

BOOST_AUTO_TEST_CASE( my_test )
{
    process_zero_separated_string(L"asdfad=bbb\x00\x00");
}

BOOST_AUTO_TEST_CASE( my_test2 )
{
    po::variables_map vm;

    dictionary info;
    
    std::vector<std::string> dirs = boost::assign::list_of("I:\\Users\\Igor\\My Documents\\ViewsGit\\crashinsight\\tdata");
    std::vector<std::string> crashdmps;

    find_dmp_files(dirs, crashdmps);

    std::string path = std::string("SRV*c:\\temp\\localsymbols*http://msdl.microsoft.com/download/symbols");
    boost::any a = boost::any(path);
    po::variable_value vv = po::variable_value(a, false);
    vm.insert(std::make_pair("symbol_path", vv));

    for(auto it = crashdmps.begin(), ite = crashdmps.end(); it != ite; ++it) {
        std::string & path = *it;
        process_crash_dmp(path, vm, info);
    }

    //BOOST_REQUIRE_EQUAL(info[std::string("cpu")], std::string("x64"));
}

