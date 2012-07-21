
#include "export.h"

#include <string>
#include <vector>

#include <boost/program_options.hpp>

namespace po = boost::program_options;


typedef std::vector<std::pair<std::string, std::string>> dictionary;

CRASHINSIGHT_API void process_zero_separated_string( const  WCHAR * buff );

CRASHINSIGHT_API HRESULT process_crash_dmp(const std::string &crashdmp, const po::variables_map &vm, dictionary &info );

CRASHINSIGHT_API void find_dmp_files( const std::vector<std::string> & scan_dirs, std::vector<std::string> &crashdmps );

