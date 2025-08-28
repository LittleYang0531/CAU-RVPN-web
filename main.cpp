#include<bits/stdc++.h>
#ifdef __linux__
#include<sys/un.h>
#include<sys/stat.h>
#include<sys/syscall.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<netinet/tcp.h>
#else
#include<Windows.h>
#endif
using namespace std;
#include"log.h"
#include"json.h"
#include"encrypt.h"
#include"httpd.h"
#include"socket.h"
#include"VPNClient.h"

string readFile(string path) {
    ifstream fin(path);
    if (!fin) return "";
    fin.seekg(0, ios::end);
    int len = fin.tellg();
    if (len == -1) return "";
    fin.seekg(0, ios::beg);
    char *ch = new char[len];
    fin.read(ch, len);
    fin.close();
    string res = string(ch, len);
    delete[] ch;
    return res;
}

Json::Value appConfig;

#include"route/login.cpp"
#include"route/loginGUI.cpp"
#include"route/proxy.cpp"

void signalHandler(int signum) {
    if (signum == SIGINT) {
        cout << "Received signal " << signum << ", exiting..." << endl;
        closeAllVPNClients();
        exit(0);
    }
}

int main(int argc, char** argv) {
    srand(time(NULL));
    
    // signal(SIGINT, signalHandler);
    // signal(SIGTERM, signalHandler);

    appConfig = json_decode(readFile("./config.json"));
    appConfig["vpn"]["ssl"] = true; // force ssl
    writeLog(LOG_LEVEL_INFO, "EasyConnect web is starting...");
    Log.logLevelId = LOG_LEVEL_ERROR;
    http_init();
    UserLogin({ thread_id: -1 }, { postdata: "username=" + appConfig["admin"]["username"].asString() + "&password=" + appConfig["admin"]["password"].asString() }, {});
    Log.logLevelId = LOG_LEVEL_INFO;

    app.setopt(HTTP_ENABLE_SSL, appConfig["server.enableSSL"].asBool());
    app.setopt(HTTP_LISTEN_HOST, appConfig["server.listenHost"].asString().c_str());
    app.setopt(HTTP_LISTEN_PORT, appConfig["server.listenPort"].asInt());
    app.setopt(HTTP_SSL_CACERT, appConfig["server.httpsCacert"].asString().c_str());
    app.setopt(HTTP_SSL_PRIVKEY, appConfig["server.httpsPrivkey"].asString().c_str());
    app.setopt(HTTP_MULTI_THREAD, appConfig["server.threadNumber"].asInt());

    app.addRoute("/api/login", UserLogin);
    app.addRoute("", UserLoginGUI);
    app.addRoute("/", UserLoginGUI);
    app.addRoute("/login", UserLoginGUI);
    app.addRoute("*", UserProxy);

    app.run();
}