// crashinsight.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <iostream>
#include <iomanip>


#include <boost/filesystem.hpp>
#include <boost/regex.hpp>


#include <windows.h>

#include "../crashinsightlib/crashinsight.h"

int process_command_line( int argc, _TCHAR **argv, po::variables_map &vm )
{
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help"                   , "produce help message")
        ("crash_dmp,z"            , po::value<std::vector<std::string>>() , "crash dmp file")
        ("symbol_path,y"          , po::value<std::string>() , "symbol path")
        ("image_path"             , po::value<std::string>() , "image path")
        ("crash_dmp_scan_dir"     , po::value<std::vector<std::string>>() , "scan directory")
        ("path_regex"             , po::value<std::vector<std::string>>() , "path regex")
        ;

    po::positional_options_description p;
    p.add("crash_dmp", -1);

    try {
        po::store(po::command_line_parser(argc, argv). options(desc).positional(p).run(), vm);
        po::notify(vm);    
    } catch ( const boost::program_options::error& e ) {
        std::cerr << "Invalid command line parameters:" << std::endl << e.what() << std::endl;
        return -1;
    }

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 0;
    }

    return 0;
}

void path_regex_extract( const std::string & crashdmp, const po::variables_map & vm, dictionary & info ) 
{
    if( !vm.count("path_regex") )
        return;

    auto res = vm["path_regex"].as<std::vector<std::string>>();

    for(auto it = res.begin(), ite = res.end(); it != ite; ++it ) {

        std::string sre = *it;
        boost::regex re;
        boost::cmatch matches;

        try {
            // Set up the regular expression for case-insensitivity
            re.assign(sre, boost::regex_constants::icase);
        } catch (boost::regex_error& e) {
            std::cout << sre << " is not a valid regular expression: \""
                << e.what() << "\"" << std::endl;
            continue;
        } if (boost::regex_match(crashdmp.c_str(), matches, re)) {
            // matches[0] contains the original string.  matches[n]
            // contains a sub_match object for each matching
            // subexpression
            for (size_t i = 1; i < matches.size(); i++) {
                // sub_match::first and sub_match::second are iterators that
                // refer to the first and one past the last chars of the
                // matching subexpression
                std::string match(matches[i].first, matches[i].second);
                info.push_back(std::make_pair(boost::lexical_cast<std::string>(i), match));
            }
        }
    }

}

std::string& xml_encode(std::string& data) {
    std::string buffer;
    buffer.reserve(data.size());
    for(size_t pos = 0; pos != data.size(); ++pos) {
        switch(data[pos]) {
        case '&':  buffer.append("&amp;");       break;
        case '\"': buffer.append("&quot;");      break;
        case '\'': buffer.append("&apos;");      break;
        case '<':  buffer.append("&lt;");        break;
        case '>':  buffer.append("&gt;");        break;
        default:   
            {
                char c = data[pos];
                buffer.append(&c, 1);
            }break;
        }
    }
    data.swap(buffer);

    return data;
}


int _tmain(int argc, _TCHAR* argv[])
{
    HRESULT hr = S_OK;

    po::variables_map vm;
    int iRet = process_command_line(argc, argv, vm);

    if( 0 != iRet ) {
        return iRet;
    }

    if( !vm.count("crash_dmp") && !vm.count("crash_dmp_scan_dir") ) {
        std::cout << "Invalid arguments for crash_dmp option" << std::endl;
        return -1;
    }

    std::vector<std::string> crash_dmp_paths;

    if( vm.count("crash_dmp") ) {
        crash_dmp_paths = vm["crash_dmp"].as<std::vector<std::string>>();
    } else {
        if( vm.count("crash_dmp_scan_dir") ) {
            std::vector<std::string> scan_dirs = vm["crash_dmp_scan_dir"].as<std::vector<std::string>>();

            find_dmp_files(scan_dirs, crash_dmp_paths);
        }
    }


    std::cout << "<crashdmps>" << std::endl;

    for( size_t i = 0, n = crash_dmp_paths.size(); i < n; i++ ) {
        dictionary info;

        const std::string &crashdmp = crash_dmp_paths[i];

        std::cerr << "Processing " << (i + 1) << "/" << n << ": " << crashdmp << "." << std::endl;

        info.push_back(std::make_pair("file", crashdmp));

        process_crash_dmp(crashdmp, vm, info);

        path_regex_extract(crashdmp, vm, info);

        std::cout << "<crashdmp ";
        std::for_each(info.begin(), info.end(), [](std::pair<std::string, std::string> & p){
            std::cout << p.first << "=\"" << xml_encode(p.second) << "\" ";
        });
        std::cout << "/>";
        std::cout << std::endl;
    }
    std::cout << "</crashdmps>" << std::endl;

    return hr;
}







