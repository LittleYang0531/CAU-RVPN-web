struct TCPPacket {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t headLength = 5;
    bool NS = false;
    bool CWR = false;
    bool ECE = false;
    bool URG = false;
    bool ACK = false;
    bool PSH = false;
    bool RST = false;
    bool SYN = false;
    bool FIN = false;
    uint16_t windowSize = 29200;
    uint16_t checksum = 0;
    uint16_t urgentPointer = 0;
    uint8_t* optionData = NULL;
    uint32_t optionDataLength = 0;
    uint8_t* data = NULL;
    uint32_t dataLength = 0;

    TCPPacket(uint16_t srcPort, uint16_t dstPort, uint8_t* data, uint32_t dataLength): srcPort(srcPort), dstPort(dstPort) {
        this->dataLength = dataLength;
        this->data = new uint8_t[dataLength];
        memcpy(this->data, data, dataLength);
    }
    TCPPacket(uint8_t* packet, uint32_t packetLength) {
        if (packetLength < 20) return;
        srcPort = (packet[0] << 8) | packet[1];
        dstPort = (packet[2] << 8) | packet[3];
        seq = (packet[4] << 24) | (packet[5] << 16) | (packet[6] << 8) | packet[7];
        ack = (packet[8] << 24) | (packet[9] << 16) | (packet[10] << 8) | packet[11];
        headLength = (packet[12] >> 4) & 0x0f;
        NS = (packet[12] & 0x01);
        CWR = (packet[13] & 0x80);
        ECE = (packet[13] & 0x40);
        URG = (packet[13] & 0x20);
        ACK = (packet[13] & 0x10);
        PSH = (packet[13] & 0x08);
        RST = (packet[13] & 0x04);
        SYN = (packet[13] & 0x02);
        FIN = (packet[13] & 0x01);
        windowSize = (packet[14] << 8) | packet[15];
        checksum = (packet[16] << 8) | packet[17];
        urgentPointer = (packet[18] << 8) | packet[19];
        optionDataLength = (headLength - 5) * 4;
        optionData = new uint8_t[optionDataLength];
        memcpy(optionData, packet + 20, optionDataLength);
        dataLength = packetLength - headLength * 4;
        this->data = new uint8_t[dataLength];
        memcpy(this->data, packet + headLength * 4, dataLength);
    }
    TCPPacket(const TCPPacket& other) {
        srcPort = other.srcPort;
        dstPort = other.dstPort;
        seq = other.seq;
        ack = other.ack;
        headLength = other.headLength;
        NS = other.NS;
        CWR = other.CWR;
        ECE = other.ECE;
        URG = other.URG;
        ACK = other.ACK;
        PSH = other.PSH;
        RST = other.RST;
        SYN = other.SYN;
        FIN = other.FIN;
        windowSize = other.windowSize;
        checksum = other.checksum;
        urgentPointer = other.urgentPointer;

        optionDataLength = other.optionDataLength;
        if (optionDataLength > 0) {
            optionData = new uint8_t[optionDataLength];
            memcpy(optionData, other.optionData, optionDataLength);
        }

        dataLength = other.dataLength;
        if (dataLength > 0) {
            data = new uint8_t[dataLength];
            memcpy(data, other.data, dataLength);
        }
    }
    ~TCPPacket() {
        if (optionData) delete[] optionData;
        if (data) delete[] data;
    }
    void setData(uint8_t* data, uint32_t length) {
        if (this->data) delete[] this->data;
        this->data = data;
        this->dataLength = length;
    }
    void setOptionData(uint8_t* data, uint32_t length) {
        assert(length % 4 == 0);
        if (optionData) delete[] optionData;
        optionData = data;
        optionDataLength = length;
        headLength = 5 + length / 4;
    }
    uint32_t getLength() {
        return headLength * 4 + dataLength;
    }
    uint8_t* toBytes() {
        int len = getLength();
        uint8_t* bytes = new uint8_t[len];
        memset(bytes, 0, len);
        bytes[0] = (srcPort >> 8) & 0xff; bytes[1] = srcPort & 0xff;
        bytes[2] = (dstPort >> 8) & 0xff; bytes[3] = dstPort & 0xff;
        bytes[4] = (seq >> 24) & 0xff; bytes[5] = (seq >> 16) & 0xff; bytes[6] = (seq >> 8) & 0xff; bytes[7] = seq & 0xff;
        bytes[8] = (ack >> 24) & 0xff; bytes[9] = (ack >> 16) & 0xff; bytes[10] = (ack >> 8) & 0xff; bytes[11] = ack & 0xff;
        bytes[12] = (headLength << 4) | (NS << 0);
        bytes[13] = (CWR << 7) | (ECE << 6) | (URG << 5) | (ACK << 4) | (PSH << 3) | (RST << 2) | (SYN << 1) | (FIN << 0);
        bytes[14] = (windowSize >> 8) & 0xff; bytes[15] = windowSize & 0xff;
        bytes[16] = (checksum >> 8) & 0xff; bytes[17] = checksum & 0xff;
        bytes[18] = (urgentPointer >> 8) & 0xff; bytes[19] = urgentPointer & 0xff;
        memcpy(bytes + 20, optionData, optionDataLength);
        memcpy(bytes + headLength * 4, data, dataLength);
        return bytes;
    }
    void calcSum(uint8_t srcIp[4], uint8_t dstIp[4]) {
        checksum = 0;
        uint8_t* pseudoHeader = new uint8_t[12];
        uint8_t* packet = toBytes();
        memset(pseudoHeader, 0, 12);

        // 填充伪头部
        pseudoHeader[0] = srcIp[0]; pseudoHeader[1] = srcIp[1]; pseudoHeader[2] = srcIp[2]; pseudoHeader[3] = srcIp[3];
        pseudoHeader[4] = dstIp[0]; pseudoHeader[5] = dstIp[1]; pseudoHeader[6] = dstIp[2]; pseudoHeader[7] = dstIp[3];
        pseudoHeader[8] = 0x00; 
        pseudoHeader[9] = 0x06;
        uint16_t tcpLength = getLength();
        pseudoHeader[10] = (tcpLength >> 8) & 0xff; pseudoHeader[11] = tcpLength & 0xff;

        uint64_t sum = 0;
        for (int i = 0; i < 12; i += 2) if (i + 1 < 12) sum += (pseudoHeader[i] << 8) + pseudoHeader[i + 1];
        for (int i = 0; i < getLength(); i += 2) {
            if (i + 1 < getLength()) sum += (packet[i] << 8) + packet[i + 1];
            else sum += (packet[i] << 8);
        }
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        checksum = ~sum & 0xffff;
        delete[] pseudoHeader;
        delete[] packet;
    }
    bool checkSum(uint8_t srcIp[4], uint8_t dstIp[4]) {
        bool tmpChecksum = checksum;
        checksum = 0;
        calcSum(srcIp, dstIp);
        bool res = checksum == tmpChecksum;
        checksum = tmpChecksum; // 恢复原来的校验和
        return res;
    }

    void output() {
        cout << "TCP Packet:" << endl;
        cout << "  Source Port: " << srcPort << endl;
        cout << "  Destination Port: " << dstPort << endl;
        cout << "  Sequence Number: " << seq << endl;
        cout << "  Acknowledgment Number: " << ack << endl;
        cout << "  Header Length: " << (int)headLength * 4 << " bytes" << endl;
        cout << "  Flags: ";
        if (NS) cout << "NS ";
        if (CWR) cout << "CWR ";
        if (ECE) cout << "ECE ";
        if (URG) cout << "URG ";
        if (ACK) cout << "ACK ";
        if (PSH) cout << "PSH ";
        if (RST) cout << "RST ";
        if (SYN) cout << "SYN ";
        if (FIN) cout << "FIN ";
        cout << endl;
        cout << "  Window Size: " << windowSize << endl;
        cout << "  Checksum: 0x" << hex << checksum << dec << endl;
        cout << "  Urgent Pointer: " << urgentPointer << endl;
    }
};

struct IPPacket {
    uint8_t version = 4;
    uint8_t headLength = 5;
    uint8_t typeOfService = 0;
    uint16_t totalLength;
    uint16_t identification = 0;
    bool DF = true;
    bool MF = false;
    uint16_t offset = 0;
    uint8_t timeToLive = 128;
    uint8_t protocol = 6;
    uint16_t checksum = 0;
    uint8_t srcIp[4];
    uint8_t dstIp[4];
    uint8_t* optionData = NULL;
    uint32_t optionDataLength = 0;
    uint8_t* data = NULL;
    uint32_t dataLength = 0;

    IPPacket(uint8_t srcIp[4], uint8_t dstIp[4], uint8_t* data, uint32_t dataLength) {
        memcpy(this->srcIp, srcIp, 4);
        memcpy(this->dstIp, dstIp, 4);
        this->data = new uint8_t[dataLength];
        memcpy(this->data, data, dataLength);
        this->dataLength = dataLength;
        this->totalLength = headLength * 4 + dataLength;
    }
    IPPacket(uint8_t* packet, uint32_t packetLength) {
        if (packetLength < 20) return;
        version = (packet[0] >> 4) & 0x0f;
        headLength = packet[0] & 0x0f;
        typeOfService = packet[1];
        totalLength = (packet[2] << 8) | packet[3];
        identification = (packet[4] << 8) | packet[5];
        DF = (packet[6] & 0x40) != 0;
        MF = (packet[6] & 0x20) != 0;
        offset = ((packet[6] & 0x1f) << 8) | packet[7];
        timeToLive = packet[8];
        protocol = packet[9];
        checksum = (packet[10] << 8) | packet[11];
        memcpy(srcIp, packet + 12, 4);
        memcpy(dstIp, packet + 16, 4);
        optionDataLength = (headLength - 5) * 4;
        if (optionDataLength > 0) {
            optionData = new uint8_t[optionDataLength];
            memcpy(optionData, packet + 20, optionDataLength);
        }
        dataLength = totalLength - headLength * 4;
        this->data = new uint8_t[dataLength];
        memcpy(this->data, packet + headLength * 4, dataLength);
    }
    IPPacket(const IPPacket& other) {
        version = other.version;
        headLength = other.headLength;
        typeOfService = other.typeOfService;
        totalLength = other.totalLength;
        identification = other.identification;
        DF = other.DF;
        MF = other.MF;
        offset = other.offset;
        timeToLive = other.timeToLive;
        protocol = other.protocol;
        checksum = other.checksum;
        memcpy(srcIp, other.srcIp, 4);
        memcpy(dstIp, other.dstIp, 4);
        optionDataLength = other.optionDataLength;
        if (optionDataLength > 0) {
            optionData = new uint8_t[optionDataLength];
            memcpy(optionData, other.optionData, optionDataLength);
        }
        dataLength = other.dataLength;
        if (dataLength > 0) {
            data = new uint8_t[dataLength];
            memcpy(data, other.data, dataLength);
        }
    }
    ~IPPacket() {
        if (data) delete[] data;
        if (optionData) delete[] optionData;
    }
    void setData(uint8_t* data, uint32_t length) {
        if (this->data) delete[] this->data;
        this->data = data;
        this->dataLength = length;
        this->totalLength = headLength * 4 + length;
    }
    void setOptionData(uint8_t* data, uint32_t length) {
        assert(length % 4 == 0);
        if (optionData) delete[] optionData;
        optionData = data;
        optionDataLength = length;
        headLength = 5 + length / 4;
        totalLength = headLength * 4 + dataLength;
    }
    uint32_t getLength() {
        return totalLength;
    }
    uint8_t* toBytes() {
        uint32_t len = getLength();
        uint8_t* bytes = new uint8_t[len];
        memset(bytes, 0, len);
        bytes[0] = (version << 4) | headLength;
        bytes[1] = typeOfService;
        bytes[2] = (totalLength >> 8) & 0xff; bytes[3] = totalLength & 0xff;
        bytes[4] = (identification >> 8) & 0xff; bytes[5] = identification & 0xff;
        bytes[6] = (DF << 6) | (MF << 5) | ((offset >> 8) & 0x1f); bytes[7] = offset & 0xff;
        bytes[8] = timeToLive;
        bytes[9] = protocol;
        bytes[10] = (checksum >> 8) & 0xff; bytes[11] = checksum & 0xff;
        memcpy(bytes + 12, srcIp, 4);
        memcpy(bytes + 16, dstIp, 4);
        memcpy(bytes + 20, optionData, optionDataLength);
        memcpy(bytes + headLength * 4, data, dataLength);
        return bytes;
    }
    void calcSum() {
        checksum = 0;
        uint8_t* packet = toBytes();
        uint64_t sum = 0;
        for (int i = 0; i < headLength * 4; i += 2) sum += (packet[i] << 8) + packet[i + 1];
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        checksum = ~sum & 0xffff;
        delete[] packet;
    }
    bool checkSum() {
        bool tmpChecksum = checksum;
        checksum = 0;
        calcSum();
        bool res = checksum == tmpChecksum;
        checksum = tmpChecksum; // 恢复原来的校验和
        return res;
    }
};

void hexDump(char* msg, int len);
int sessionCount = 0;
void* VPNSession_work_thread(void* arg);
time_t waitTime = 120 * 1000 * 1000;
time_t clock3() {
	return chrono::duration_cast<chrono::microseconds>(chrono::system_clock::now().time_since_epoch()).count();
}
struct VPNSession {
    HttpRequest conn;
    HttpRequest sendConn;
    HttpRequest recvConn;
    map<int, queue<IPPacket> > packets;
    bool closed = false;
    pthread_t pt;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    VPNSession(HttpRequest conn, HttpRequest sendConn, HttpRequest recvConn): conn(conn), sendConn(sendConn), recvConn(recvConn) {
        ofstream ofs("./data/data.pcap", ios::binary);
        ofs.write("\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00", 24);
        ofs.close();
        pthread_create(&pt, NULL, VPNSession_work_thread, this);
        pthread_mutex_init(&mutex, NULL);
    }

    void sendPacket(IPPacket packet) {
        ofstream ofs("./data/data.pcap", ios::binary | ios::app);
        time_t now = clock3();
        char* timestamp = new char[8];
        timestamp[0] = (now / 1000000) & 0xff;
        timestamp[1] = ((now / 1000000) >> 8) & 0xff;
        timestamp[2] = ((now / 1000000) >> 16) & 0xff;
        timestamp[3] = ((now / 1000000) >> 24) & 0xff;
        timestamp[4] = (now % 1000000) & 0xff;
        timestamp[5] = ((now % 1000000) >> 8) & 0xff;
        timestamp[6] = ((now % 1000000) >> 16) & 0xff;
        timestamp[7] = ((now % 1000000) >> 24) & 0xff;
        char* len = new char[4];
        uint32_t packetLength = packet.getLength() + 14;
        len[0] = packetLength & 0xff;
        len[1] = (packetLength >> 8) & 0xff;
        len[2] = (packetLength >> 16) & 0xff;
        len[3] = (packetLength >> 24) & 0xff;
        pthread_mutex_lock(&mutex);
        ofs.write(timestamp, 8);
        delete[] timestamp;
        ofs.write(len, 4);
        ofs.write(len, 4);
        delete[] len;
        ofs.write("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00", 14);
        ofs.write((char*)packet.toBytes(), packet.getLength());
        ofs.close();
        // cout << "VPNClient: Send packet (len = " << packet.getLength() << "): " << endl;
        // hexDump((char*)packet.toBytes(), packet.getLength());
        sendConn.send((char*)packet.toBytes(), packet.getLength());
        pthread_mutex_unlock(&mutex);
    }

    IPPacket recvPacket(int port) {
        time_t st = clock3();
        while (packets[port].size() == 0 && !closed && clock3() - st < waitTime) 
        #ifdef __linux__
            usleep(1000 * 10);
        #else 
            Sleep(10);
        #endif
        if (!packets[port].size()) return IPPacket(NULL, 0);
        IPPacket packet = packets[port].front();
        packets[port].pop();
        return packet; 
    }

    void close() {
        pthread_cancel(pt);
        ::close(conn.conn.conn);
        ::close(sendConn.conn.conn);
        ::close(recvConn.conn.conn);
        closed = true;
    }
};

void* VPNSession_work_thread(void* arg) {
    VPNSession* session = (VPNSession*)arg;
    while (true) {
        int len2 = -1;
        // cout << 1 << endl;
        // pthread_mutex_lock(&session->mutex);
        uint8_t* recvData = (uint8_t*)session->recvConn.recv(1024 * 1024, len2);
        // pthread_mutex_unlock(&session->mutex);
        // cout << len2 << endl;
        IPPacket packet(recvData, len2);
        delete[] recvData;
        // createFile();
        ofstream ofs("./data/data.pcap", ios::binary | ios::app);
        time_t now = clock3();
        char* timestamp = new char[8];
        timestamp[0] = (now / 1000000) & 0xff;
        timestamp[1] = ((now / 1000000) >> 8) & 0xff;
        timestamp[2] = ((now / 1000000) >> 16) & 0xff;
        timestamp[3] = ((now / 1000000) >> 24) & 0xff;
        timestamp[4] = (now % 1000000) & 0xff;
        timestamp[5] = ((now % 1000000) >> 8) & 0xff;
        timestamp[6] = ((now % 1000000) >> 16) & 0xff;
        timestamp[7] = ((now % 1000000) >> 24) & 0xff;
        char* len = new char[4];
        uint32_t packetLength = packet.getLength() + 14;
        len[0] = packetLength & 0xff;
        len[1] = (packetLength >> 8) & 0xff;
        len[2] = (packetLength >> 16) & 0xff;
        len[3] = (packetLength >> 24) & 0xff;
        // pthread_mutex_lock(&session->mutex);
        ofs.write(timestamp, 8);
        delete[] timestamp;
        ofs.write(len, 4);
        ofs.write(len, 4);
        delete[] len;
        ofs.write("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00", 14);
        ofs.write((char*)packet.toBytes(), packet.getLength());
        ofs.close();
        // pthread_mutex_unlock(&session->mutex);
        // cout << "VPNClient: Recv packet (len = " << packet.getLength() << "): " << endl;
        // hexDump((char*)packet.toBytes(), packet.getLength());
        TCPPacket Packet(packet.data, packet.dataLength);
        session->packets[Packet.dstPort].push(packet);
    }
}

void hexDump(char* msg, int len) {
    for (int i = 0; i < len; i += 16) {
        printf("%04x: ", i);
        for (int j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", (unsigned char)msg[i + j]);
            else printf("   ");
        }
        printf(" | ");
        for (int j = 0; j < 16; j++) {
            if (i + j < len) printf("%c", isprint(msg[i + j]) ? msg[i + j] : '.');
            else printf(" ");
        }
        printf("\n");
    }
}

struct OptionData {
    int type;
    int len;
    int64_t value;
};
map<int, OptionData> parseOptionData(uint8_t* data, uint32_t length) {
    map<int, OptionData> options;
    for (uint32_t i = 0; i < length; ) {
        int type = data[i];
        if (type == 0) break;
        if (type == 1) {
            i++;
            continue;
        }
        int len = data[i + 1];
        if (len < 2 || i + len > length) break;
        int value = 0;
        for (int j = 2; j < len; j++) value = (value << 8) | data[i + j];
        options[type] = { type, len - 2, value };
        i += len;
    }
    return options;
}

map<int, OptionData> getDefaultOptionData() {
    map<int, OptionData> options;
    options[8] = { 8, 8, time(NULL) }; // Timestamp
    return options;
}

uint8_t* createOptionData(map<int, OptionData> options, uint32_t& length) {
    length = 0;
    for (auto v : options) length += 2 + v.second.len;
    while (length % 4 != 0) length++;
    uint8_t* data = new uint8_t[length];
    uint32_t index = 0;
    for (auto v : options) {
        data[index++] = v.first;
        data[index++] = 2 + v.second.len;
        for (int i = 0; i < v.second.len; i++) data[index++] = (v.second.value >> ((v.second.len - 1 - i) * 8)) & 0xff;
    }
    while (index < length) data[index++] = 1;
    return data;
}

void setOptionData(TCPPacket& packet, map<int, OptionData> options) {
    uint32_t length = 0;
    uint8_t* data = createOptionData(options, length);
    packet.setOptionData(data, length);
}

int VPNClinet_BIO_read(BIO *bio, char *out, int outl);
int VPNClinet_BIO_write(BIO *bio, const char *in, int inl);
long VPNClinet_BIO_ctrl(BIO *bio, int cmd, long num, void *ptr);

struct VPNClient {
    VPNSession* session;
    uint8_t srcIp[4];
    uint8_t dstIp[4];
    uint16_t srcPort;
    uint16_t dstPort;
    int MSS = 1460;
    uint32_t currSeq = 0;
    uint32_t currAck = 0;
    bool closed = true;
    vector<char> recvBuffer;
    vector<char> sslRecvBuffer;
    bool isSSL = false;
    SSL* ssl;
    bool error = false;

    void addToList();
    void deleteFromList();

    VPNClient(
        VPNSession* session,
        uint8_t srcIp[4], uint8_t dstIp[4], 
        uint16_t srcPort, uint16_t dstPort
    ): session(session), srcPort(srcPort), dstPort(dstPort) {
        memcpy(this->srcIp, srcIp, 4);
        memcpy(this->dstIp, dstIp, 4);
    }

    bool created = false;
    void sendPacket(IPPacket packet) {
        session->sendPacket(packet);
    }
    IPPacket recvPacket() {
        IPPacket packet = session->recvPacket(srcPort);
        // hexDump((char*)packet.toBytes(), packet.getLength());
        return packet;
    }

    void connect() {
        auto options2 = getDefaultOptionData();
        options2[2] = { 2, 2, MSS }; // MSS option
        options2[3] = { 3, 1, 7 }; // Window scale option
        options2[4] = { 4, 0, 0 }; // SACK permitted option

        currSeq = rand() & 0xffffffff;
        TCPPacket Packet1(srcPort, dstPort, NULL, 0);
        setOptionData(Packet1, options2);
        Packet1.seq = currSeq++;
        Packet1.SYN = true;
        Packet1.calcSum(srcIp, dstIp);
        IPPacket ipPacket1(srcIp, dstIp, Packet1.toBytes(), Packet1.getLength());
        ipPacket1.calcSum();
        sendPacket(ipPacket1);
        // cout << "VPNClient: Send SYN packet (len = " << ipPacket1.getLength() << "): " << endl;
        // hexDump((char*)ipPacket1.toBytes(), ipPacket1.getLength());
        // Packet1.output();

        IPPacket ipPacket2 = recvPacket();
        TCPPacket Packet2(ipPacket2.data, ipPacket2.dataLength);
        currAck = Packet2.seq + 1;
        map<int, OptionData> options = parseOptionData(Packet2.optionData, Packet2.optionDataLength);
        if (options.find(2) != options.end()) {
            MSS = options[2].value;
            // cout << "VPNClient: Recv MSS option: " << options[2].value << endl;
        }
        // cout << "VPNClient: Recv SYN/ACK packet (len = " << ipPacket2.getLength() << "): " << endl;
        // hexDump((char*)ipPacket2.toBytes(), ipPacket2.getLength());
        // Packet2.output();
        if (Packet2.SYN == 0) {

            return;
        }

        TCPPacket Packet3(srcPort, dstPort, NULL, 0);
        setOptionData(Packet3, getDefaultOptionData());
        Packet3.seq = currSeq;
        Packet3.ack = currAck;
        Packet3.ACK = true;
        Packet3.calcSum(srcIp, dstIp);
        IPPacket ipPacket3(srcIp, dstIp, Packet3.toBytes(), Packet3.getLength());
        ipPacket3.calcSum();
        sendPacket(ipPacket3);
        // cout << "VPNClient: Send ACK packet (len = " << ipPacket3.getLength() << "): " << endl;
        // hexDump((char*)ipPacket3.toBytes(), ipPacket3.getLength());
        // Packet3.output();

        addToList();
        closed = false;
    }

    void SSL_Connect(bool ignoreSSL) {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_keylog_callback(ctx, [](const SSL *ssl, const char *line) {
            ofstream keylogFile("./data/keylog.txt", ios::app);
            keylogFile << line << endl;
            keylogFile.close();
        });
        SSL* ssl;
        if (ignoreSSL) SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        // else SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        ssl = SSL_new(ctx);
        // SSL_set_max_proto_version(ssl, TLS1_2_VERSION);
        BIO_METHOD *bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "Custom BIO");
        BIO_meth_set_read(bio_method, VPNClinet_BIO_read);
        BIO_meth_set_write(bio_method, VPNClinet_BIO_write);
        BIO_meth_set_ctrl(bio_method, VPNClinet_BIO_ctrl); // 用于关闭、获取状态等
        BIO *bio = BIO_new(bio_method);
        void *conn = this; // 你的自定义上下文，如 socket fd
        BIO_set_data(bio, conn);

        // SSL_set_ciphersuites(ssl, "TLS_RSA_WITH_AES_128_CBC_SHA256");
        // SSL_set_cipher_list(ssl, "AES128-SHA");
        SSL_set_bio(ssl, bio, bio); // 读写 BIO 可以是同一个
        // cout << "Start SSL connect..." << endl;
        if (SSL_connect(ssl) == -1) {
            // hexDump(recvBuffer.data(), recvBuffer.size());
            // cout << "VPNClient: SSL connect failed: " << ERR_error_string(ERR_get_error(), NULL) << endl;
            error = true;
        } else isSSL = true, this->ssl = ssl;
        // const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
        // printf("Negotiated cipher: %s\n", SSL_CIPHER_get_name(cipher));
        // // 获取 session ticket
        // const unsigned char* ticket; size_t length;
        // SSL_SESSION_get0_ticket(SSL_get_session(ssl), &ticket, &length);
        // for (int i = 0; i < length; i++) {
        //     printf("%02x", ticket[i]);
        // }
        // printf("\n");
        // cout << "SSL connect success!" << endl;
    }

    void send(const char* data, int length) {
        if (closed) {

            return;
        }
        int sendLength = min(length, MSS);
        TCPPacket Packet(srcPort, dstPort, (uint8_t*)data, sendLength);
        setOptionData(Packet, getDefaultOptionData());
        uint32_t tmpSeq = currSeq;
        Packet.seq = currSeq;
        Packet.ack = currAck;
        Packet.PSH = sendLength == length;
        Packet.ACK = true;
        Packet.calcSum(srcIp, dstIp);
        IPPacket ipPacket(srcIp, dstIp, Packet.toBytes(), Packet.getLength());
        ipPacket.calcSum();
        sendPacket(ipPacket);
        currSeq += sendLength;
        // cout << "VPNClient: Send data packet (len = " << ipPacket.getLength() << "): " << endl;
        // hexDump((char*)Packet.data, Packet.dataLength);
        // Packet.output();

        // 接收 ACK
        if (length == sendLength) {
            // IPPacket ipPacket2 = recvPacket();
            // TCPPacket Packet2(ipPacket2.data, ipPacket2.dataLength);
            // // cout << "VPNClient: Recv ACK packet (len = " << ipPacket2.getLength() << "): " << endl;
            // // hexDump((char*)ipPacket2.toBytes(), ipPacket2.getLength());
            // // Packet2.output();
            // // currSeq = Packet2.ack;
            // char* data = (char*)Packet2.data;
            // int length = Packet2.dataLength;
            // currAck = Packet2.seq + Packet2.dataLength;
            // recvBuffer.insert(recvBuffer.end(), data, data + length);
        } else send(data + length - sendLength, length - length + sendLength);    
    }

    char* recv(int &length) {
        // if (recvBuffer.size() > 0) {
        //     // cout << "Return " << recvBuffer.size() << " bytes from buffer." << endl;
        //     length = recvBuffer.size();
        //     char* res = new char[length];
        //     memcpy(res, recvBuffer.data(), length);
        //     recvBuffer.clear();
        //     return res;
        // }

        if (closed) {

            length = -1;
            return NULL;
        }

        time_t startTime = clock2(); int packetNum = 0;
        vector<uint8_t*> data; vector<uint32_t> dataLength; vector<uint32_t> seqs;
        bool shouldClose = false; uint32_t ack, seq;
        uint32_t tmpAck = currAck;
        uint32_t maxSeq = 1e9; length = 0;
        while (true) {
            IPPacket ipPacket = recvPacket();
            TCPPacket Packet(ipPacket.data, ipPacket.dataLength);

            // cout << "VPNClient: Recv data packet (len = " << ipPacket.getLength() << "): " << endl;
            // hexDump((char*)Packet.data, Packet.dataLength);
            // Packet.output();
            // if (!Packet.checkSum(ipPacket.srcIp, ipPacket.dstIp)) {
            //     cout << "VPNClient: Checksum error!" << endl;
            // }
            bool valid = false;
            if (Packet.dataLength && Packet.seq == currAck) {
                currSeq = Packet.ack;
                currAck = Packet.seq + Packet.dataLength;
                length += Packet.dataLength;
                uint8_t* dataPtr = new uint8_t[Packet.dataLength];
                memcpy(dataPtr, Packet.data, Packet.dataLength);
                data.push_back(dataPtr);
                dataLength.push_back(Packet.dataLength);
                seqs.push_back(Packet.seq);
                valid = true;
            }
            if (Packet.dataLength) packetNum++;

            if (Packet.FIN) { 
                maxSeq = Packet.seq + Packet.dataLength;
                shouldClose = true; 
                ack = Packet.ack;
                seq = Packet.seq;
                break; 
            }

            if (packetNum == 1) {
                // 发送 ACK
                TCPPacket Packet2(srcPort, dstPort, NULL, 0);
                setOptionData(Packet2, getDefaultOptionData());
                Packet2.seq = currSeq;
                Packet2.ack = currAck;
                Packet2.ACK = true;
                Packet2.calcSum(srcIp, dstIp);
                IPPacket ipPacket2(srcIp, dstIp, Packet2.toBytes(), Packet2.getLength());
                ipPacket2.calcSum();
                sendPacket(ipPacket2);
                // cout << "VPNClient: Send ACK packet (len = " << ipPacket2.getLength() << "): " << endl;
                // hexDump((char*)ipPacket2.toBytes(), ipPacket2.getLength());
                // Packet2.output();

                startTime = clock2();
                packetNum = 0;
            }
            if (valid) {
                if (Packet.PSH) {
                    maxSeq = Packet.seq + Packet.dataLength;
                    break;
                }
            }
            // cout << "VPNClient: Recv packet " << packetNum << " (seq = " << Packet.seq << ", ack = " << Packet.ack << ", dataLength = " << Packet.dataLength << ", length = " << length << ")" << endl;
        }

        int totalLength = 0;
        totalLength = maxSeq - tmpAck;
        // cout << totalLength << " " << maxSeq << " " << tmpAck << endl;
        // if (minSeq != tmpAck || length != totalLength) {
        //     cout << "TCP Previous segment not captured. Retrying..." << endl;
        //     currAck = tmpAck;
        //     for (int i = 0; i < data.size(); i++) delete[] data[i];
        //     return recv(length);
        // }
        uint8_t* PacketData = new uint8_t[totalLength];
        bool* captured = new bool[totalLength];
        memset(captured, 0, totalLength);
        for (int i = 0; i < data.size(); i++) {
            memcpy(PacketData + (seqs[i] - tmpAck), data[i], dataLength[i]);
            memset(captured + (seqs[i] - tmpAck), true, dataLength[i]);
            delete[] data[i];
        }
        bool error = false;
        for (int i = 0; i < totalLength; i++) error |= !captured[i];
        delete[] captured;
        if (error) {
            cout << "TCP Previous segment not captured. Retrying..." << endl;
            currAck = tmpAck;
            for (int i = 0; i < data.size(); i++) delete[] data[i];
            return recv(length);
        }

        if (shouldClose) {
            close2(ack, seq);
            return (char*)PacketData;
        }
            
        // 发送 ACK
        if (packetNum) {
            TCPPacket Packet2(srcPort, dstPort, NULL, 0);
            setOptionData(Packet2, getDefaultOptionData());
            Packet2.seq = currSeq;
            Packet2.ack = currAck;
            Packet2.ACK = true;
            Packet2.calcSum(srcIp, dstIp);
            IPPacket ipPacket2(srcIp, dstIp, Packet2.toBytes(), Packet2.getLength());
            ipPacket2.calcSum();
            sendPacket(ipPacket2);
            // cout << "VPNClient: Send ACK packet (len = " << ipPacket2.getLength() << "): " << endl;
            // hexDump((char*)ipPacket2.toBytes(), ipPacket2.getLength());
            // Packet2.output();    
        }
        
        return (char*)PacketData;
    }

    char* recv(int targetLength, int &realLength) {
        // cout << recvBuffer.size() << " " << targetLength << endl;
        while (recvBuffer.size() < targetLength) {
            int len = -1;
            // cout << recvBuffer.size() << " " << targetLength << endl;
            char* data = recv(len);
            // cout << len << endl;
            if (data == NULL || len <= 0) break;
            // cnt += len;
            recvBuffer.insert(recvBuffer.end(), data, data + len);
            delete[] data;
        }
        realLength = min((int)recvBuffer.size(), targetLength);
        char* res = new char[targetLength];
        memset(res, 0, targetLength);
        if (recvBuffer.size() <= targetLength) {
            memcpy(res, recvBuffer.data(), recvBuffer.size());
            recvBuffer.clear();
            return res;
        }
        memcpy(res, recvBuffer.data(), targetLength);
        recvBuffer.erase(recvBuffer.begin(), recvBuffer.begin() + targetLength);
        return res;
    }

    // 被动 close
    void close2(uint32_t ack, uint32_t seq) {
        cout << "closed" << endl;
        TCPPacket Packet4(srcPort, dstPort, NULL, 0);
        setOptionData(Packet4, getDefaultOptionData());
        Packet4.seq = ack;
        Packet4.ack = seq + 1;
        Packet4.ACK = true;
        Packet4.calcSum(srcIp, dstIp);
        IPPacket ipPacket4(srcIp, dstIp, Packet4.toBytes(), Packet4.getLength());
        ipPacket4.calcSum();
        sendPacket(ipPacket4);
        // cout << "VPNClient.close(): Send ACK packet (len = " << ipPacket4.getLength() << "): " << endl;
        // hexDump((char*)ipPacket4.toBytes(), ipPacket4.getLength());

        deleteFromList();
        closed = true;
    }

    // 主动 close
    void close() {
        if (closed) return;
        if (isSSL) SSL_shutdown(ssl);
        // 发送 FIN
        TCPPacket Packet(srcPort, dstPort, NULL, 0);
        setOptionData(Packet, getDefaultOptionData());
        Packet.seq = currSeq;
        Packet.ack = currAck;
        Packet.FIN = true;
        Packet.ACK = true;
        Packet.calcSum(srcIp, dstIp);
        IPPacket ipPacket(srcIp, dstIp, Packet.toBytes(), Packet.getLength());
        ipPacket.calcSum();
        sendPacket(ipPacket);
        while (true) {
            IPPacket ipPacket3 = recvPacket();
            TCPPacket Packet3(ipPacket3.data, ipPacket3.dataLength);
            // cout << "VPNClient.close(): Recv FIN packet (len = " << ipPacket3.getLength() << "): " << endl;
            // hexDump((char*)ipPacket3.toBytes(), ipPacket3.getLength());
            // Packet3.output();
            if (!Packet3.FIN) {
                if (Packet3.ack == currSeq + 1) continue;
                // 发送 ACK
                TCPPacket Packet(srcPort, dstPort, NULL, 0);
                setOptionData(Packet, getDefaultOptionData());
                Packet.seq = Packet3.ack;
                Packet.ack = Packet3.seq + Packet3.dataLength;
                Packet.ACK = true;
                Packet.calcSum(srcIp, dstIp);
                IPPacket ipPacket(srcIp, dstIp, Packet.toBytes(), Packet.getLength());
                ipPacket.calcSum();
                sendPacket(ipPacket);
                continue;
            }
            close2(Packet3.ack, Packet3.seq);
            deleteFromList();
            break;
        }
    }

    void SSL_send(const char* data, int length) {
        if (!isSSL || closed) {
            return;
        }
        int ret = SSL_write(ssl, data, length);
        if (ret < 0) error = true;
    }

    char* SSL_recv(int &length) {
        if (!isSSL || closed) {
            length = -1;
            return NULL;
        }
        char* data = new char[1024 * 1024];
        // cout << "Start recv" << endl;
        length = SSL_read(ssl, data, 1024 * 1024);
        if (length < 0) error = true;
        // cout << "SSL recv" << length << " " << ERR_error_string(ERR_get_error(), NULL) << endl;
        return data;
    }

    char* SSL_recv(int targetLength, int &realLength) {
        if (!isSSL) {
            realLength = -1;
            return NULL;
        }
        while (sslRecvBuffer.size() < targetLength) {
            int len = -1;
            char* recvData = SSL_recv(len);
            if (len <= 0) { delete[] recvData; break; }
            sslRecvBuffer.insert(sslRecvBuffer.end(), recvData, recvData + len);
            delete[] recvData;
        }
        realLength = min((int)sslRecvBuffer.size(), targetLength);
        char* res = new char[realLength];
        memcpy(res, sslRecvBuffer.data(), realLength);
        sslRecvBuffer.erase(sslRecvBuffer.begin(), sslRecvBuffer.begin() + realLength);
        return res;
    }

    void sendData(const char* data, int length) {
        if (isSSL) SSL_send(data, length);
        else send(data, length);
    }

    char* recvData(int &length) {
        if (isSSL) return SSL_recv(length);
        else return recv(length);
    }

    char* recvData(int targetLength, int &realLength) {
        if (isSSL) return SSL_recv(targetLength, realLength);
        else return recv(targetLength, realLength);
    }
};

vector<VPNClient*> clients;
void VPNClient::addToList() {
    clients.push_back(this);
}
void VPNClient::deleteFromList() {
    for (auto it = clients.begin(); it != clients.end(); ++it) {
        if (*it == this) {
            clients.erase(it);
            break;
        }
    }
}

void closeAllVPNClients() {
    for (auto client : clients) if (!client->closed) client->close();
    clients.clear();
}

int cnt = 0;
vector<string> datas;
int VPNClinet_BIO_read(BIO *bio, char *out, int outl) {
    VPNClient* client = (VPNClient*)BIO_get_data(bio);
    int ret = 0;
    // cout << "Recving " << outl << " bytes" << endl;
    char* data = client->recv(outl, ret);
    memcpy(out, data, ret);
    delete[] data;
    // cout << cnt << " Recv " << ret << "/" << outl << "bytes" << endl;
    // hexDump(out, ret);
    if (ret <= 0) {
        if (errno == EAGAIN) BIO_set_retry_read(bio);
        return 0; // 返回 0 表示无数据可读
    }
    return ret;
}

int VPNClinet_BIO_write(BIO *bio, const char *in, int inl) {
    VPNClient* client = (VPNClient*)BIO_get_data(bio);
    client->send(in, inl);
    int ret = inl;
    // cout << "Send " << ret << "bytes" << endl;
    // hexDump((char*)in, inl);
    if (ret != inl) {
        if (errno == EAGAIN) BIO_set_retry_write(bio);
        return -1; // 返回 -1 表示写入失败
    }
    return inl;
}

long VPNClinet_BIO_ctrl(BIO *bio, int cmd, long num, void *ptr) {
    if (cmd == BIO_CTRL_FLUSH) {
        // 实现 flush 逻辑
        return 1;
    }
    else if (cmd == BIO_CTRL_GET_CLOSE) {
        return 0; // 返回 0 表示不关闭 socket
    } else if (cmd == BIO_CTRL_SET_CLOSE) {
        VPNClient* ctx = (VPNClient*)BIO_get_data(bio);
        ctx->close();
        return 1;
    }
    return 0;
}