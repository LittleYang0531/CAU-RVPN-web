string getContent(string source, string prefix, string suffix, int pt = 0) {
    int st = source.find(prefix, pt) + prefix.size();
    int ed = source.find(suffix, st);
    if (st == -1 || ed == -1) return "";
    return source.substr(st, ed - st);
}

string hex2str(unsigned char* uc, int len) {
    stringstream ss;
    for (int i = 0; i < len; i++)
        ss << hex << setw(2) << setfill('0') << (unsigned int)uc[i];
    return ss.str();
}

string encryptPKCS1v15(string text, string key, int exp) {
    RSA* rsa = RSA_new();
    BIGNUM* n = BN_new();
    BN_hex2bn(&n, key.c_str());
    BIGNUM *e = BN_new();
    BN_set_word(e, exp);
    RSA_set0_key(rsa, n, e, nullptr);

    unsigned char* encrypted = new unsigned char[RSA_size(rsa)];

    int result = RSA_public_encrypt(
        text.size(),
        reinterpret_cast<const unsigned char*>(text.c_str()),
        encrypted,
        rsa,
        RSA_PKCS1_PADDING
    );

    RSA_free(rsa);

    return hex2str(encrypted, result);
}

HttpRequest getRecvConn(string sessionId, string twfId, uint8_t ip[4]) {
    auto R = EasyProtocal(appConfig["vpn"]["web"].asString(), appConfig["vpn"]["port"].asInt(), appConfig["vpn"]["ssl"].asBool());
    char* message = new char[64];
    memset(message, 0, 64);
    message[0] = 0x06;
    memcpy(message + 4, sessionId.substr(0, 32).c_str(), 32);
    memcpy(message + 36, twfId.c_str(), 16);
    memcpy(message + 60, ip, 4);
    // cout << "getRecvConn: send message(len = " << 64 << "):" << endl;
    // hexDump(message, 64);
    R.send(message, 64);
    delete[] message;

    int len = -1;
    char* response = R.recv(36, len);
    // cout << "getRecvConn: recv response(len = " << len << "):" << endl;
    // hexDump(response, len);
    if (len < 1 || response[0] != 0x01) {
        delete[] response;
        return HttpRequest({ isSSL: false });
    }

    delete[] response;
    return R;
}

HttpRequest getSendConn(string sessionId, string twfId, uint8_t ip[4]) {
    auto R = EasyProtocal(appConfig["vpn"]["web"].asString(), appConfig["vpn"]["port"].asInt(), appConfig["vpn"]["ssl"].asBool());
    char* message = new char[64];
    memset(message, 0, 64);
    message[0] = 0x05;
    memcpy(message + 4, sessionId.substr(0, 32).c_str(), 32);
    memcpy(message + 36, twfId.c_str(), 16);
    memcpy(message + 60, ip, 4);
    // cout << "getSendConn: send message(len = " << 64 << "):" << endl;
    // hexDump(message, 64);
    R.send(message, 64);
    delete[] message;

    int len = -1;
    char* response = R.recv(36, len);
    // cout << "getSendConn: recv response(len = " << len << "):" << endl;
    // hexDump(response, len);
    if (len < 1 || response[0] != 0x02) {
        delete[] response;
        return HttpRequest({ isSSL: false });
    }

    delete[] response;
    return R;
}

map<string, string> dns;
struct allowIp {
    uint8_t startIp[4], endIp[4];
    uint16_t startPort, endPort;
};
vector<allowIp> allowIps;
map<string, string> tokens;
map<string, VPNSession*> sessions;

auto UserLogin = [](client_conn conn, http_request request, param argv) {
    auto GET = getParam(request);
    auto POST = postParam(request);
    string username = GET["username"], password = GET["password"];
    if (username == "" || password == "") username = POST["username"], password = POST["password"];
    if (username == "" || password == "") {
        putRequest(conn, 403, __api_default_response);
        Json::Value res;
        res["code"] = 403;
        res["success"] = false;
        res["msg"] = "Username or password is empty.";
        send(conn, json_encode(res));
        exitRequest(conn);
        return;
    }

    // GET /por/login_auth.csp
    HttpRequest R = fetch(appConfig["vpn"]["web"].asString(), appConfig["vpn"]["port"].asInt(), appConfig["vpn"]["ssl"].asBool());
    stringstream ss;
    ss << "GET /por/login_auth.csp?apiversion=1 HTTP/1.1\r\n";
    ss << "Host: " << appConfig["vpn"]["web"].asString() << "\r\n";
    ss << "User-Agent: EasyConnect Client/1.0.0\r\n";   
    ss << "\r\n";
    R.sendRequest(ss.str());
    string header = R.recvHeader();
    string data = R.recvContent();

    string twfId = getContent(data, "<TwfID>", "</TwfID>");
    string rsaKey = getContent(data, "<RSA_ENCRYPT_KEY>", "</RSA_ENCRYPT_KEY>");
    string rsaExp = getContent(data, "<RSA_ENCRYPT_EXP>", "</RSA_ENCRYPT_EXP>");
    if (rsaExp == "") rsaExp = "65537";
    string csrfCode = getContent(data, "<CSRF_RAND_CODE>", "</CSRF_RAND_CODE>");
    string passwd = encryptPKCS1v15(password + "_" + csrfCode, rsaKey, atoi(rsaExp.c_str()));

    // POST /por/login_psw.csp
    string formData = "mitm_result=&svpn_req_randcode=" + csrfCode + "&svpn_name=" + username + "&svpn_password=" + passwd + "&svpn_rand_code=";
    ss.str("");
    ss << "POST /por/login_psw.csp?anti_replay=1&encrypt=1&apiversion=1 HTTP/1.1\r\n";
    ss << "Host: " << appConfig["vpn"]["web"].asString() << "\r\n";
    ss << "User-Agent: EasyConnect Client/1.0.0\r\n";
    ss << "Content-Type: application/x-www-form-urlencoded\r\n";
    ss << "Content-Length: " << formData.size() << "\r\n";
    ss << "Cookie: TWFID=" << twfId << "\r\n";
    ss << "\r\n";
    ss << formData;
    R = fetch(appConfig["vpn"]["web"].asString(), appConfig["vpn"]["port"].asInt(), appConfig["vpn"]["ssl"].asBool());
    R.sendRequest(ss.str());
    header = R.recvHeader();
    data = R.recvContent();

    if (data.find("<NextService>auth/sms</NextService>") != string::npos || data.find("<NextAuth>2</NextAuth>") != string::npos) {
        putRequest(conn, 403, __api_default_response);
        Json::Value res;
        res["code"] = 403;
        res["success"] = false;
        res["msg"] = "SMS authentication is not supported yet.";
        res["twfId"] = twfId;
        send(conn, json_encode(res));
        exitRequest(conn);
    }

    if (data.find("<NextService>auth/token</NextService>") != string::npos || data.find("<NextServiceSubType>totp</NextServiceSubType>") != string::npos) {
        putRequest(conn, 403, __api_default_response);
        Json::Value res;
        res["code"] = 403;
        res["success"] = false;
        res["msg"] = "TOTP authentication is not supported yet.";
        res["twfId"] = twfId;
        send(conn, json_encode(res));
        exitRequest(conn);
    }

    if (data.find("<NextAuth>-1</NextAuth>") == string::npos && data.find("<NextAuth>") != string::npos) {
        putRequest(conn, 403, __api_default_response);
        Json::Value res;
        res["code"] = 403;
        res["success"] = false;
        res["msg"] = "Unknown authentication.";
        res["twfId"] = twfId;
        send(conn, json_encode(res));
        exitRequest(conn);
    }

    if (data.find("<Result>1</Result>") == string::npos) {
        putRequest(conn, 403, __api_default_response);
        Json::Value res;
        res["code"] = 403;
        res["success"] = false;
        res["msg"] = getContent(data, "<Message><![CDATA[", "]]></Message>");
        send(conn, json_encode(res));
        exitRequest(conn);
    }
    twfId = getContent(data, "<TwfID>", "</TwfID>");

    // GET /por/conf.csp
    ss.str("");
    ss << "GET /por/conf.csp?apiversion=1 HTTP/1.1\r\n";
    ss << "Host: " << appConfig["vpn"]["web"].asString() << "\r\n";
    ss << "User-Agent: EasyConnect Client/1.0.0\r\n";
    ss << "Cookie: TWFID=" << twfId << "\r\n";
    ss << "\r\n";
    R = fetch(appConfig["vpn"]["web"].asString(), appConfig["vpn"]["port"].asInt(), appConfig["vpn"]["ssl"].asBool());
    R.sendRequest(ss.str());
    header = R.recvHeader();
    string conf = R.recvContent();
    
    // GET /por/rclist.csp
    ss.str("");
    ss << "GET /por/rclist.csp?apiversion=1 HTTP/1.1\r\n";
    ss << "Host: " << appConfig["vpn"]["web"].asString() << "\r\n";
    ss << "User-Agent: EasyConnect Client/1.0.0\r\n";
    ss << "Cookie: TWFID=" << twfId << "\r\n";
    ss << "\r\n";
    R = fetch(appConfig["vpn"]["web"].asString(), appConfig["vpn"]["port"].asInt(), appConfig["vpn"]["ssl"].asBool());
    R.sendRequest(ss.str());
    header = R.recvHeader();
    string rclist = R.recvContent();
    if (allowIps.size() == 0) {
        map<string, string> dns;
        vector<allowIp> allowIps;
        // 解析 dns
        string dnsData = getContent(rclist, "<Dns dnsserver=\"\" data=\"", "\"");
        auto dnsList = explode(";", dnsData);
        for (auto& d : dnsList) {
            if (d == "") continue;
            auto parts = explode(":", d);
            if (parts.size() != 3) continue;
            dns.insert({ parts[1], parts[2] });
            dns.insert({ parts[2], parts[2] });
            // cout << "Add DNS: " << parts[1] << " -> " << parts[2] << endl;
            // cout << "Add DNS: " << parts[2] << " -> " << parts[2] << endl;
        }
        // 解析 allowIp
        string rcData = getContent(rclist, "<Rcs>", "</Rcs>");
        int st = 0;
        while (true) {
            if (rcData.find("host=\"", st) == string::npos) break;
            string host = getContent(rcData, "host=\"", "\"", st);
            string port = getContent(rcData, "port=\"", "\"", st);
            st = rcData.find("/>", st) + 1;
            auto hosts = explode(";", host);
            auto ports = explode(";", port);
            for (int i = 0; i < min(hosts.size(), ports.size()); i++) {
                string host = hosts[i], port = ports[i];
                if (port == "0") continue;

                // 处理 host
                uint8_t startIp[4] = { 0, 0, 0, 0 };
                uint8_t endIp[4] = { 0, 0, 0, 0 };
                if (host.find("//") != string::npos || !isdigit(host[0])) {
                    string domain = host.substr(host.find("//") + 2);
                    if (domain.find("/") != string::npos) domain = domain.substr(0, domain.find("/"));
                    if (domain.find("?") != string::npos) domain = domain.substr(0, domain.find("?"));
                    if (domain.find(":") != string::npos) domain = domain.substr(0, domain.find(":"));
                    if (dns.find(domain) != dns.end()) {
                        sscanf(dns[domain].c_str(), "%hhd.%hhd.%hhd.%hhd", &startIp[0], &startIp[1], &startIp[2], &startIp[3]);
                        memcpy(endIp, startIp, 4);
                    } else {
                        if (gethostbyname(domain.c_str()) == NULL) continue;
                        string ip = string(inet_ntoa(*(struct in_addr*)gethostbyname(domain.c_str())->h_addr_list[0]));
                        sscanf(ip.c_str(), "%hhd.%hhd.%hhd.%hhd", &startIp[0], &startIp[1], &startIp[2], &startIp[3]);
                        memcpy(endIp, startIp, 4);
                    }
                } else {
                    if (host.find("~") != string::npos) {
                        sscanf(host.substr(0, host.find("~")).c_str(), "%hhd.%hhd.%hhd.%hhd", &startIp[0], &startIp[1], &startIp[2], &startIp[3]);
                        sscanf(host.substr(host.find("~") + 1).c_str(), "%hhd.%hhd.%hhd.%hhd", &endIp[0], &endIp[1], &endIp[2], &endIp[3]);
                    } else {
                        sscanf(host.c_str(), "%hhd.%hhd.%hhd.%hhd", &startIp[0], &startIp[1], &startIp[2], &startIp[3]);
                        memcpy(endIp, startIp, 4);
                    }
                }

                // 处理 port
                uint16_t startPort = 0, endPort = 0;
                if (port.find("~") != string::npos) {
                    startPort = atoi(port.substr(0, port.find("~")).c_str());
                    endPort = atoi(port.substr(port.find("~") + 1).c_str());
                } else {
                    startPort = endPort = atoi(port.c_str());
                }

                allowIps.push_back({
                    startIp: { startIp[0], startIp[1], startIp[2], startIp[3] },
                    endIp: { endIp[0], endIp[1], endIp[2], endIp[3] },
                    startPort: startPort,
                    endPort: endPort
                });
                // cout << "Added Allow IP: " << (int)startIp[0] << "." << (int)startIp[1] << "." << (int)startIp[2] << "." << (int)startIp[3] 
                //     << " ~ " << (int)endIp[0] << "." << (int)endIp[1] << "." << (int)endIp[2] << "." << (int)endIp[3]
                //     << " Port: " << startPort << " ~ " << endPort << endl;
            }
        }
        ::dns = dns;
        ::allowIps = allowIps;
    }
    string sessionId = getSessionId(R.ssl);

    // Query IP
    R = EasyProtocal(appConfig["vpn"]["web"].asString(), appConfig["vpn"]["port"].asInt(), appConfig["vpn"]["ssl"].asBool());
    char* message = new char[64];
    memset(message, 0, 64);
    memcpy(message + 4, sessionId.substr(0, 32).c_str(), 32);
    memcpy(message + 36, twfId.c_str(), 16);
    memset(message + 60, 0xff, 4);
    R.send(message, 64);
    int len = -1;
    char* response = R.recv(36, len);
    if (len < 8 || response[0] != 0x00) {
        delete[] response;
        putRequest(conn, 500, __api_default_response);
        Json::Value res;
        res["code"] = 500;
        res["success"] = false;
        res["msg"] = "Failed to query IP.";
        send(conn, json_encode(res));
        exitRequest(conn);
        return;
    }
    string ip = "";
    for (int i = 4; i < 8; i++) ip += to_string((int)(unsigned char)response[i]) + (i == 8 - 1 ? "" : ".");

    if (tokens.find(username) != tokens.end())
        if (sessions.find(tokens[username]) != sessions.end()) {
            sessions[tokens[username]]->close();
            delete sessions[tokens[username]];
        }
    tokens[username] = sessionId;
    uint8_t ipData[4];
    for (int i = 0; i < 4; i++) ipData[i] = (unsigned char)response[i + 4];
    reverse(ipData, ipData + 4);
    VPNSession* session = new VPNSession(
        R,
        getSendConn(sessionId, twfId, ipData), 
        getRecvConn(sessionId, twfId, ipData)
    );
    sessions[tokens[username]] = session;

    Json::Value res;
    res["code"] = 200;
    res["success"] = true;
    res["msg"] = "";
    res["sessionId"] = sessionId;
    res["twfId"] = twfId;
    res["ip"] = ip;
    res["ipData"].resize(0);
    for (int i = 4; i < 8; i++) res["ipData"].append((int)(unsigned char)response[i]);
    delete[] response;
    putRequest(conn, 200, __api_default_response);
    send(conn, json_encode(res));
    exitRequest(conn);
};