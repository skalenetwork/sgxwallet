//
// Created by kladko on 11/19/19.
//

std::vector<std::string> BLSutils::SplitString(std::string& str, const std::string& delim){
    std::vector<std::string> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string token = str.substr(prev, pos-prev);
        if (!token.empty()) tokens.push_back(token);
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());

    return tokens;
}

bool checkPolyName (std::string polyName){

}