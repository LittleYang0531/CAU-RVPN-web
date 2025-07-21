auto UserLoginGUI = [](client_conn conn, http_request request, param argv) {
    string file = "./login.html";
    ifstream fin(file);
    fin.seekg(0, ios::end);
    int len = fin.tellg();
    fin.seekg(0, ios::beg);
    char* content = new char[len];
    fin.read(content, len);
    fin.close();
    string response = string(content, len);
    delete[] content;
    putRequest(conn, 200, __default_response);
    send(conn, response);
    exitRequest(conn);
};