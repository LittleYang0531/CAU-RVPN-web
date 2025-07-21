string str_replace(string from, string to, string source) {
    string result = source;
	int st = 0, wh = result.find(from.c_str(), st);
    // cout << result << " " << from << " " << wh << endl;
	while (wh != string::npos) {
        result.replace(wh, from.size(), to.c_str());
		st = wh + to.size();
		wh = result.find(from.c_str(), st);
	} 
    return result;
}

map<string, string> lastHost;

bool allowIpCheck(uint8_t ip[4], int port) {
    for (int i = 0; i < allowIps.size(); i++) {
        auto allow = allowIps[i];
        if (
            ip[0] >= allow.startIp[0] && ip[0] <= allow.endIp[0] &&
            ip[1] >= allow.startIp[1] && ip[1] <= allow.endIp[1] &&
            ip[2] >= allow.startIp[2] && ip[2] <= allow.endIp[2] &&
            ip[3] >= allow.startIp[3] && ip[3] <= allow.endIp[3] &&
            port >= allow.startPort && port <= allow.endPort
        ) return true;
    }
    return false;
}

auto UserProxy = [](client_conn conn, http_request request, param argv) {
    auto COOKIE = cookieParam(request);
    string totalSessionString = COOKIE["sessionId"] + COOKIE["twfId"] + COOKIE["ip"];
    if (sessions.find(COOKIE["sessionId"]) == sessions.end()) {
        putRequest(conn, 403, __api_default_response);
        Json::Value res;
        res["code"] = 403;
        res["success"] = false;
        res["msg"] = "Session not found.";
        send(conn, json_encode(res));
        exitRequest(conn);
        return;
    }

    string cookieString = "";
    for (auto v : COOKIE) {
        if (set<string>({ "sessionId", "twfId", "ip" }).count(v.first)) continue;
        cookieString += v.first + "=" + v.second + "; ";
    }
    string path = "/";
    string domain = "";
    {
        string host = request.path.substr(1);
        if (host.substr(0, 8) != "https://" && host.substr(0, 7) != "http://") {
            if (lastHost.find(totalSessionString) != lastHost.end()) host = lastHost[totalSessionString] + "/" + host;
            else {
                putRequest(conn, 403, __api_default_response);
                Json::Value res;
                res["code"] = 403;
                res["success"] = false;
                res["msg"] = "Invalid URL.";
                send(conn, json_encode(res));
                exitRequest(conn);
                return;
            }
        }
        request.path = "/" + host;
        host = host.substr(host.find("//") + 2);
        if (host.find("/") != string::npos) path = host.substr(host.find("/")), host = host.substr(0, host.find("/"));
        if (host.find("?") != string::npos) path = "/" + host.substr(host.find("?")), host = host.substr(0, host.find("?"));
        domain = host;
    }
    string requestHeader = request.method + " " + path + " " + request.protocol + "\r\n";
    for (auto header : request.argv) {
        string key = header.first;
        if (key == "host") header.second = domain;
        if (key == "referer") {
            if (header.second.substr(0, appConfig["server.name"].asString().size()) == appConfig["server.name"].asString())
                header.second = header.second.substr(appConfig["server.name"].asString().size());
            if (header.second.substr(0, 8) != "https://" && header.second.substr(0, 7) != "http://")
                if (lastHost.find(totalSessionString) != lastHost.end()) header.second = lastHost[totalSessionString] + header.second;
            // cout << header.second << endl;
        }
        if (key == "cookie") {
            if (cookieString == "") continue;
            header.second = cookieString;
        }
        for (int i = 0; i < key.size(); i++) if (i == 0 || key[i - 1] == '-') key[i] = toupper(key[i]);
        requestHeader += key + ": " + header.second + "\r\n";
    }
    requestHeader += "\r\n";
    requestHeader += request.postdata;

    if (COOKIE.find("sessionId") == COOKIE.end() || COOKIE.find("twfId") == COOKIE.end() || COOKIE.find("ip") == COOKIE.end()) {
        putRequest(conn, 403, __api_default_response);
        Json::Value res;
        res["code"] = 403;
        res["success"] = false;
        res["msg"] = "sessionId, twfId or ip is missing.";
        send(conn, json_encode(res));
        exitRequest(conn);
        return;
    }
    uint8_t ip[4];
    sscanf(COOKIE["ip"].c_str(), "%hhd.%hhd.%hhd.%hhd", &ip[0], &ip[1], &ip[2], &ip[3]);

    // DNS 解析
    string host = request.path.substr(1);
    bool isHttps = false;
    if (host.substr(0, 8) == "https://") {
        isHttps = true;
        host = host.substr(8);
    } else if (host.substr(0, 7) == "http://") {
        host = host.substr(7);
    } else {
        putRequest(conn, 403, __api_default_response);
        Json::Value res;
        res["code"] = 403;
        res["success"] = false;
        res["msg"] = "Invalid URL.";
        send(conn, json_encode(res));
        exitRequest(conn);
        return;
    }
    if (host.find("/") != string::npos) host = host.substr(0, host.find("/"));
    if (host.find("?") != string::npos) host = host.substr(0, host.find("?"));
    int port = isHttps ? 443 : 80;
    if (host.find(":") != string::npos) {
        port = stoi(host.substr(host.find(":") + 1));
        host = host.substr(0, host.find(":"));
    }
    // for (auto v : dns) cout << v.first << " -> " << v.second << endl;
    // if (dns.find(host) == dns.end()) {
    //     putRequest(conn, 403, __api_default_response);
    //     Json::Value res;
    //     res["code"] = 403;
    //     res["success"] = false;
    //     res["msg"] = "DNS resolution failed(Maybe the request host is not in DNS list).";
    //     send(conn, json_encode(res));
    //     exitRequest(conn);
    //     return;
    // }
    string destIpStr = "";
    if (dns.find(host) != dns.end()) destIpStr = dns[host];
    else {
        if (gethostbyname(host.c_str()) == NULL) {
            putRequest(conn, 403, __api_default_response);
            Json::Value res;
            res["code"] = 403;
            res["success"] = false;
            res["msg"] = "DNS resolution failed.";
            send(conn, json_encode(res));
            exitRequest(conn);
            return;
        }
        destIpStr = string(inet_ntoa(*(struct in_addr*)gethostbyname(host.c_str())->h_addr_list[0]));
    }
    uint8_t destIp[4];
    sscanf(destIpStr.c_str(), "%hhd.%hhd.%hhd.%hhd", &destIp[0], &destIp[1], &destIp[2], &destIp[3]);
    if (allowIpCheck(destIp, port) == false) {
        if (allowIpCheck(destIp, 80)) {
            isHttps = false;
            port = 80;
        } else if (allowIpCheck(destIp, 443)) {
            isHttps = true;
            port = 443;
        } else {
            putRequest(conn, 403, __api_default_response);
            Json::Value res;
            res["code"] = 403;
            res["success"] = false;
            res["msg"] = "You are not allowed to access to " + destIpStr + ":" + to_string(port) + ".";
            send(conn, json_encode(res));
            exitRequest(conn);
            return;
        }
    }
    int srcPort = rand() % 50000 + 10000;
    cout << "UserProxy: request to " << (isHttps ? "https://" : "http://") << host << ":" << port << " (IP: " << destIpStr << ")" << endl;
    cout << "UserProxy: from " << COOKIE["ip"] << ":" << srcPort << endl;
    lastHost[totalSessionString] = (isHttps ? "https://" : "http://") + host;
    if (!(isHttps && port == 443 || !isHttps && port == 80)) lastHost[totalSessionString] += ":" + to_string(port);

    VPNClient vpnClient = VPNClient(sessions[COOKIE["sessionId"]], ip, destIp, srcPort, port);
    vpnClient.connect();
    if (isHttps) {
        vpnClient.SSL_Connect(false);
        if (!vpnClient.isSSL) {
            vpnClient.close();
            putRequest(conn, 500, __api_default_response);
            Json::Value res;
            res["code"] = 500;
            res["success"] = false;
            res["msg"] = ERR_error_string(ERR_get_error(), NULL);
            send(conn, json_encode(res));
            exitRequest(conn);
            return;
        }
    }
    vpnClient.sendData(requestHeader.c_str(), requestHeader.size());
    if (vpnClient.error) {
        vpnClient.close();
        putRequest(conn, 500, __api_default_response);
        Json::Value res;
        res["code"] = 500;
        res["success"] = false;
        res["msg"] = ERR_error_string(ERR_get_error(), NULL);
        send(conn, json_encode(res));
        exitRequest(conn);
    }

    string res = "";
    while (true) {
        int len = -1;
        char* data = vpnClient.recvData(1, len);
        if (vpnClient.error) {
            vpnClient.close();
            putRequest(conn, 500, __api_default_response);
            Json::Value res;
            res["code"] = 500;
            res["success"] = false;
            res["msg"] = ERR_error_string(ERR_get_error(), NULL);
            send(conn, json_encode(res));
            exitRequest(conn);
        }
        if (len == 0) exit(0);
        res.push_back(data[0]);
        delete[] data;
        if (res.size() >= 4 && res.substr(res.size() - 4) == "\r\n\r\n") break;
    }
    cout << "UserProxy: Response Header (len = " << res.size() << ")" << endl;
    // for (auto v : dns) {
        res = str_replace("HttpOnly", "", res);
        int pt = 0;
        while (true) {
            pt = res.find("Path=/", pt);
            if (pt == string::npos) break;
            pt += 6;
            int pt2 = res.find(";", pt);
            res = res.replace(pt, pt2 - pt, "");
            pt++;
        }
        res = str_replace("http", appConfig["server.name"].asString() + "http", res);
    // }

    auto headers = explode("\r\n", res);
    int dataLength = -1;
    for (auto v : headers) {
        if (v.find("Content-Length: ") == 0 || v.find("content-length: ") == 0) {
            dataLength = atoi(v.substr(v.find(":") + 1).c_str());
            break;
        }
    }
    string realData = "";
    if (dataLength > 0) {
        int len = -1;
        char* data = vpnClient.recvData(dataLength, len);
        if (vpnClient.error) {
            vpnClient.close();
            putRequest(conn, 500, __api_default_response);
            Json::Value res;
            res["code"] = 500;
            res["success"] = false;
            res["msg"] = ERR_error_string(ERR_get_error(), NULL);
            send(conn, json_encode(res));
            exitRequest(conn);
        }
        realData = string(data, len);
    } else if (dataLength == -1) {
        if (vpnClient.isSSL) realData.insert(realData.end(), vpnClient.sslRecvBuffer.begin(), vpnClient.sslRecvBuffer.end());
        else realData.insert(realData.end(), vpnClient.recvBuffer.begin(), vpnClient.recvBuffer.end());
        // cout << "UserProxy: Response Content (len = " << realData.size() << ")" << endl;
        while (true) {
            if (realData.size() >= 5 && realData.substr(realData.size() - 5) == "0\r\n\r\n") break;
            int len = -1;
            char* data = vpnClient.recvData(len);
            // if (len == 0) break;
            if (vpnClient.error) {
                vpnClient.close();
                putRequest(conn, 500, __api_default_response);
                Json::Value res;
                res["code"] = 500;
                res["success"] = false;
                res["msg"] = ERR_error_string(ERR_get_error(), NULL);
                send(conn, json_encode(res));
                exitRequest(conn);
            }
            if (len > 0) realData.insert(realData.end(), data, data + len);
            delete[] data;
        }
    }
    cout << "UserProxy: Content (len = " << realData.size() << ", correct = " << dataLength << ")" << endl;

    // 内容替换
    // for (auto v : dns) {
        // realData = str_replace("http://", appConfig["server.name"].asString() + "http://", realData);
        // realData = str_replace("https://", appConfig["server.name"].asString() + "https://", realData);
    // }
    // cout << "UserProxy: Content (len = " << realData.size() << ")" << endl;

    // int len = 0;
    // char* data = vpnClient.recv(len);
    // cout << "UserProxy: recv response(len = " << len << ")" << endl;
    // string res = "";
    // if (data != NULL && len > 0) res = string(data, len); 
    // cout << res.substr(res.size() - 4096) << endl;

    // putRequest(conn, 200, __default_response);
    send(conn, res);
    send(conn, realData);
    vpnClient.close();
    exitRequest(conn);
};