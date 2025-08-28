const string errorKey = [](){
    string key = "";
    for (int i = 0; i < 256; i++) key += char(rand() % 26 + 'a');
    return key;
}();

#ifndef __linux__
#define disableSocketUnix
#endif

struct Connection {
    bool isUnix;
    int conn;

    bool send(string msg) {
        int64_t len = msg.size();
        for (int i = 0; i < 8; i++) msg = char(len & ((1 << 8) - 1)) + msg, len >>= 8;

        int64_t send = 0;
        while(true) {
            int64_t s = ::send(conn, msg.substr(send).c_str(), msg.size() - send, 0);
            if (s == -1) {
                // writeLog(LOG_LEVEL_ERROR, "Failed to send message! Errno: %d", &errno);
                return false;
            }
            send += s;
            if (send == msg.size()) return true;
        }
    }

    string recv() {
        char *len = new char[8];
        int s = ::recv(conn, len, 8, 0);
        if (s != 8) {
            delete[] len;
            return errorKey;
        }

        int64_t msgLen = 0;
        for (int i = 0; i < 8; i++) msgLen <<= 8, msgLen += (unsigned char)len[i];
        delete[] len;

        if (msgLen == 0) return "";

        char *msg = new char[msgLen];
        int64_t recv = 0;
        while(true) {
            int64_t s = ::recv(conn, msg + recv, msgLen - recv, 0);
            if (s == -1) {
                // writeLog(LOG_LEVEL_ERROR, "Failed to recv message! Error: %d", &errno);
                delete[] msg;
                return errorKey;
            }
            recv += s;
            if (recv == msgLen) break;
        }

        string result = string(msg, msgLen);
        delete[] msg;
        return result;
    }
};

struct Server {
    bool isUnix;
    int sock, conn;
    sockaddr_in clientAddr;
    #ifndef disableSocketUnix
    sockaddr_un clientSock;
    #endif

    Server(string host, int port): isUnix(false) {
        sockaddr_in serverAddr;

        #ifdef __linux__
        bzero(&serverAddr, sizeof(serverAddr));
        #else
        WORD w_req = MAKEWORD(2, 2);
        WSADATA wsadata; int err;
        err = WSAStartup(w_req, &wsadata);
        if (err != 0) {

        }
        if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wHighVersion) != 2) {

        }
        #endif

        // 创建套接字
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = inet_addr(host.c_str());
        serverAddr.sin_port = htons(port);
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            
        }

        // 绑定
        #ifdef __linux__
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        #endif
        int ret = bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        if (ret < 0) {
            
        }

        // 设置监听
        ret = listen(sock,1);
        if (ret < 0) {
            
        }
    }
    
    #ifndef disableSocketUnix
    Server(string sockPath): isUnix(true) {
        // 一定要先把上一个 sock 文件删了
        unlink(sockPath.c_str());

        sockaddr_un serverAddr;

        #ifdef __linux__
        bzero(&serverAddr, sizeof(serverAddr));
        #endif

        // 创建套接字
        serverAddr.sun_family = AF_LOCAL;
        strcpy(serverAddr.sun_path, sockPath.c_str());
        sock = socket(PF_LOCAL, SOCK_STREAM, 0);
        if (sock < 0) {
            
        }

        // 绑定
        int ret = bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        if (ret < 0) {
            
        }

        // 设置监听
        ret = listen(sock,1);
        if (ret < 0) {
            
        }
    }
    #endif

    Connection accept() {
        #ifdef __linux__
        uint32_t clientAddrLength;
        #else
        int clientAddrLength;
        #endif
        #ifndef disableSocketUnix
        clientAddrLength = isUnix ? sizeof clientSock : sizeof clientAddr;
        if (isUnix) conn = ::accept(sock, (struct sockaddr*)&clientSock, &clientAddrLength);
        else conn = ::accept(sock, (struct sockaddr*)&clientAddr, &clientAddrLength);
        #else
        clientAddrLength = sizeof clientAddr;
        conn = ::accept(sock, (struct sockaddr*)&clientAddr, &clientAddrLength);
        #endif
        if (conn < 0) {

        }
        return Connection({
            isUnix: isUnix,
            conn: conn
        });
    }
};

struct Client {
    bool isUnix;
    int sock, conn;
    sockaddr_in serverAddr;
    #ifndef disableSocketUnix
    sockaddr_un serverSock;
    #endif

    Client(string host, int port): isUnix(false) {
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = inet_addr(host.c_str());
        serverAddr.sin_port = htons(port);
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {

        }
    }

    #ifndef disableSocketUnix
    Client(string sockPath): isUnix(true) {
        serverSock.sun_family = AF_LOCAL;
        strcpy(serverSock.sun_path, sockPath.c_str());
        sock = socket(PF_LOCAL, SOCK_STREAM, 0);
        if (sock < 0) {

        }
    }
    #endif

    Connection connect() {
        #ifndef disableSocketUnix
        if (isUnix) conn = ::connect(sock, (struct sockaddr*)&serverSock, sizeof(serverSock));
        else conn = ::connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        #else
        conn = ::connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        #endif
        if (conn < 0) {

        }
        return Connection({
            isUnix: isUnix,
            conn: sock
        });
    }
};

struct HttpRequest {
    Connection conn;
    SSL* ssl;
    bool isSSL;
    int contentLength = -1;

    void send(char* request, int len) {
        int res = 0;
        if (isSSL) res = SSL_write(ssl, request, len);
        else res = ::send(conn.conn, request, len, 0);
    }
    char* recv(int target, int& len) {
        char* ch = new char[target];
        // cout << 1 << endl;
        if (isSSL) len = SSL_read(ssl, ch, target);
        else len = ::recv(conn.conn, ch, target, 0);
        // cout << len << endl;
        return ch;
    }
    void sendRequest(string request) {
        send((char*)request.c_str(), request.size());
    }
    string recvHeader() {
        string header = "";
        while (true) {
            int len = -1;
            char* data = recv(1, len);
            if (len < 0) {
                delete[] data;
                return header;
            }
            header += string(data, len);
            delete[] data;
            if (header.size() >= 4 && header.substr(header.size() - 4) == "\r\n\r\n") break;
        }
        auto headers = explode("\r\n", header);
        for (auto v : headers) {
            for (int i = 0; i < v.size(); i++) v[i] = tolower(v[i]);
            if (v.substr(0, 15) == "content-length:") contentLength = stoi(v.substr(15));
        }
        return header;
    }
    string recvContent() {
        if (contentLength == -1) {
            int len = -1;
            char* data = recv(1024 * 1024, len);
            if (len < 0) {
                delete[] data;
                return "";
            }
            string res = string(data, len);
            delete[] data;
            return res;
        } else {
            string data = "";
            while (data.size() < contentLength) {
                int len = -1;
                char* chunk = recv(contentLength - data.size(), len);
                if (len < 0) {
                    delete[] chunk;
                    return data;
                }
                data += string(chunk, len);
                delete[] chunk;
            }
            return data;
        }
    }
};

string getSessionId(SSL* ssl) {
    SSL_SESSION* session = SSL_get_session(ssl);
    if (!session) return "";

    unsigned int session_id_length;
    const unsigned char* session_id = SSL_SESSION_get_id(session, &session_id_length);

    stringstream ss;
    for (unsigned int i = 0; i < session_id_length; i++)
        ss << hex << setw(2) << setfill('0') << (int)(unsigned char)session_id[i];
    return ss.str();
}

HttpRequest fetch(string host, int port, bool isSSL = false, bool ignoreSSL = false) {
    HttpRequest res = HttpRequest();

    string ip = [&](){
        auto res = gethostbyname(host.c_str());
        return string(inet_ntoa(*(struct in_addr*)res->h_addr_list[0]));
    }();
    Client client(ip, port);
    Connection conn2 = client.connect();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL* ssl;
    if (ignoreSSL) SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    if (isSSL) {
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, conn2.conn);
        if (SSL_connect(ssl) == -1) {

        }
    }

    res.conn = conn2;
    res.ssl = ssl;
    res.isSSL = isSSL;
    return res;
}

HttpRequest EasyProtocal(string host, int port, bool isSSL = false, bool ignoreSSL = false) {
    HttpRequest res = HttpRequest();

    string ip = [&](){
        auto res = gethostbyname(host.c_str());
        return string(inet_ntoa(*(struct in_addr*)res->h_addr_list[0]));
    }();
    Client client(ip, port);
    Connection conn2 = client.connect();
    #ifdef __linux__
    int optval = 1;
    setsockopt(conn2.conn, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(int));
    optval = 15; setsockopt(conn2.conn, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof(int));
    optval = 5; setsockopt(conn2.conn, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof(int));
    optval = 3; setsockopt(conn2.conn, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof(int));
    #else
    tcp_keepalive keepalive;
    keepalive.onoff = 1;
    keepalive.keepalivetime = 15 * 1000;
    keepalive.keepaliveinterval = 5 * 1000;
    // keepalive.keepaliveprobes = 3;

    DWORD bytesReturned;
    WSAIoctl(
        conn2.conn,
        SIO_KEEPALIVE_VALS,
        &keepalive,
        sizeof(keepalive),
        NULL,
        0,
        &bytesReturned,
        NULL,
        NULL
    );
    #endif

    SSL_CTX *ctx = SSL_CTX_new(TLSv1_1_client_method());
    SSL* ssl;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    if (isSSL) {
        SSL_CTX_set_ssl_version(ctx, TLSv1_1_client_method());
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
        SSL_CTX_set_ciphersuites(ctx, "TLS_RSA_WITH_RC4_128_SHA:TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
        SSL_CTX_set_cipher_list(ctx, "DEFAULT:@SECLEVEL=0");
        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);
        ssl = SSL_new(ctx);
        SSL_session_reused(ssl);
        SSL_set_connect_state(ssl);

        unsigned char *buffer = new unsigned char[32];
        memset(buffer, 0, 32);
        memcpy(buffer, "L3IP", 4);
        SSL_SESSION* session = SSL_SESSION_new();
        SSL_SESSION_set1_id(session, buffer, 32);
        SSL_SESSION_set_protocol_version(session, TLS1_1_VERSION);
        SSL_set_session(ssl, session);
        delete[] buffer;

        SSL_set_fd(ssl, conn2.conn);
        int ret = SSL_connect(ssl);
        if (ret < 0) {

        }
    }

    res.conn = conn2;
    res.ssl = ssl;
    res.isSSL = isSSL;
    return res;
}