#include "mainwindow.h"
#include "ui_mainwindow.h"
char priorityStr[8][20] = { "NORMAL", "IDLE" , "REALTIME", "HIGH", "NULL", "ABOVENORMAL", "BELOWNORMAL" };
info recvInfo;
char TypeStr[128][128] = {
    "",                      // 索引0不用或者保留为空
    "MessageBoxA",          // 1 - 弹窗
    "MessageBoxW",          // 2 - 弹窗
    "WriteFile",            // 3 - 写文件
    "ReadFile",             // 4 - 读文件
    "CreateFileA",          // 5 - 打开或创建文件
    "CreateFileW",          // 6 - 打开或创建文件
    "DeleteFileA",          // 7 - 删除文件
    "DeleteFileW",          // 8 - 删除文件
    "GetFileAttributesW",   // 9 - 获取文件属性
    "GetFileSize",          // 10 - 获取文件大小
    "MoveFileW",            // 11 - 移动或重命名文件
    "MoveFileExW",          // 12 - 移动文件（支持更多选项）
    "Send",                 // 13 - 发送数据
    "SendTo",               // 14 - 发送数据到指定地址
    "WSASend",              // 15 - 发送数据
    "Recv",                 // 16 - 接收数据
    "RecvFrom",             // 17 - 接收远程数据
    "WSARecv",              // 18 - 接收数据
    "Connect",              // 19 - 建立连接
    "WSAConnect",           // 20 - 建立连接
    "gethostbyname",        // 21 - 域名解析
    "getaddrinfo",          // 22 - 域名/IP解析
    "socket",               // 23 - 创建套接字
    "closesocket",          // 24 - 关闭套接字
    "CreateProcessA",       // 25 - 创建进程（ANSI版本）
    "CreateProcessW",       // 26 - 创建进程（Unicode版本）
    "ShellExecuteW",        // 27 - 执行shell命令（Unicode版本）
    "CreateThread",         // 28 - 创建线程
    "ExitThread",           // 29 - 终止线程
    "LoadLibraryA",         // 30 - 加载动态库（ANSI版本）
    "LoadLibraryW",         // 31 - 加载动态库（Unicode版本）
    "LoadLibraryExW",       // 32 - 加载动态库（扩展参数，Unicode版本）
    "GetProcAddress",       // 33 - 获取函数地址
    "VirtualAllocEx",       // 34 - 在远程进程中分配内存
    "WriteProcessMemory",   // 35 - 向远程进程写入内存
    "CreateRemoteThread",   // 36 - 在远程进程中创建线程
    "CreateWindowExA",      // 37 - 创建窗口（扩展样式，ANSI版本）
    "CreateWindowExW",      // 38 - 创建窗口（扩展样式，Unicode版本）
    "RegisterClassA",       // 39 - 注册窗口类（ANSI版本）
    "RegisterClassW",       // 40 - 注册窗口类（Unicode版本）
    "SetWindowLongA",       // 41 - 设置窗口属性（ANSI版本）
    "SetWindowLongW",       // 42 - 设置窗口属性（Unicode版本）
    "ShowWindow",           // 43 - 显示窗口
    "DestroyWindow",        // 44 - 销毁窗口
    "GetAsyncKeyState",     // 45 - 检查某个键被按下还是释放
    "GetKeyState",          // 46 - 获取指定虚拟键的状态
    "RegisterHotKey",       // 47 - 注册一个系统范围的热键
    "SetWindowsHookExA",    // 48 - 安装钩子
    "GetCursorPos",         // 49 - 获取鼠标光标坐标
    "SetCursorPos",         // 50 - 将光标移动到指定位置
    "VirtualFree",          // 51 - 释放虚拟内存
    "NtQuerySystemInformation", // 52 - 获取系统级别信息
    "NtReadVirtualMemory"   // 53 - 读取指定进程的虚拟内存
};
// MainWindow构造函数
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    initUi();
}
// myThread构造函数
myThread::myThread(QObject* parent)
    : QThread(parent)
{
    // 构造函数体，可以是空的
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::initUi(){
    connect(&ThreadA, SIGNAL(newProcessName(QString)), this, SLOT(on_Get_newProcessName(QString)));
    connect(&ThreadA, SIGNAL(newProcessID(QString)), this, SLOT(on_Get_newProcessID(QString)));
    connect(&ThreadA, SIGNAL(newProcessPriority(QString)), this, SLOT(on_Get_newProcessPriority(QString)));
    connect(&ThreadA, SIGNAL(newProcessModules(QString)), this, SLOT(on_Get_newProcessModules(QString)));
    connect(&ThreadA, SIGNAL(newInfo()), this, SLOT(on_Get_newInfo()));
    connect(&ThreadA, SIGNAL(newInfo(QString, int)), this, SLOT(on_Get_newInfo(QString, int)));
}

void MainWindow::on_selectFileButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(
        this, tr("打开文件"),
        "D:\\RedPill", //默认目录
        tr("Image files(*.txt *.exe);;All files (*.*)"));// 文件过滤器

    if (fileName.isEmpty())
    {
        QMessageBox mesg;
        mesg.warning(this, "warning", "open file failed");
        return;
    }
    else
    {
        ui->fileTextEdit->setText(fileName);
    }
}

void myThread::init(const char* path){
    running = true; //给线程的主循环做条件用
    memset(fileName, 0, sizeof(fileName));//清除一下全局变量的值
    memset(filePath, 0, sizeof(filePath));
    // 把文件路径给filePath
    strcpy(filePath, path);
    qDebug() << "filePath" << filePath;
    // 把文件名给fileName
    int len = strlen(filePath);

    for (int i = 0; filePath[i] != 0; i++) {
        if (filePath[i] == '/') {
            filePath[i] = '\\';
        }
    }

    while(filePath[len-1]!='\\'){
        len--;
    }
    strcpy(fileName, filePath+len);//filePath指向整个路径起始位置 filePath+len指向文件名开始的地方
    qDebug() << "fileName" << fileName;


}

void myThread::run(){
    emit newProcessName(QString(QLatin1String(fileName))); // 发射newProcessName Qt信号
    HANDLE hSemaphore = CreateSemaphoreW(NULL, 0, 1, L"mySemaphore");
    if (hSemaphore == NULL) {
        qDebug() << "创建信号量失败，错误码：" << GetLastError();
        return;
    }
    HANDLE hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(info), L"ShareMemory");
    if (hMapFile == NULL) {
        qDebug() << "创建共享内存失败，错误码：" << GetLastError();
        CloseHandle(hSemaphore);
        return;
    }
    LPVOID lpBase = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpBase == NULL) {
        qDebug() << "映射共享内存失败，错误码：" << GetLastError();
        CloseHandle(hMapFile);
        CloseHandle(hSemaphore);
        return;
    }

    STARTUPINFOA startupInfo = { 0 };
    PROCESS_INFORMATION  processInformation = { 0 };
    BOOL bSuccess = CreateProcessA("D:\\RedPill\\injector\\x64\\Release\\injector.exe",
                                   filePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startupInfo, &processInformation);

    char temp[256];

    //ProcessId 进程ID
    sprintf(temp, "%d", processInformation.dwProcessId);
    emit newProcessID(QString(QLatin1String(temp)));
    //进程优先级
    sprintf(temp, "%s", priorityStr[GetProcessPriority(processInformation.hProcess)]); //QString内部会复制字符串内容，而不是引用原始指针，所以覆盖无所谓
    emit newProcessPriority(QString(QLatin1String(temp)));

    //清空temp
    memset(temp, 0, sizeof(temp));

    // 枚举进程中的模块
    HMODULE Module[256]; //存模块句柄的数组
    DWORD cbNeeded; //存储所有模块句柄所需的字节数
    int moduleNumber;
    char moduleNameBuffer[256]; //接收模块文件名的缓冲区
    if (EnumProcessModules(processInformation.hProcess, Module, sizeof(Module), &cbNeeded))
    {
        // 模块个数
        moduleNumber = cbNeeded / sizeof(HMODULE);
        for (int i = 0; i < moduleNumber; i++) {
            GetModuleFileNameA(Module[i], moduleNameBuffer, 256);
            strcat(temp, moduleNameBuffer);
            strcat(temp, "\n");
        }
        emit newProcessModules(QString(QLatin1String(temp)));
    } else {
        DWORD error = GetLastError(); // 获取最新错误码
        qDebug() << "EnumProcessModules获取模块失败" << error;
    }

    //主循环：不断等待并处理新信息
    while(running){
        if (WaitForSingleObject(hSemaphore, 10) == WAIT_OBJECT_0) {
            //从共享内存ipBase中复制大小为info的结构体的数据到 recvInfo
            memcpy(&recvInfo, lpBase, sizeof(info));
            emit newInfo();
            checkFunc();

        }
    }

}

void myThread::checkFunc(){
    unsigned  temp;
    switch (recvInfo.type)
    {
        /**----------------------------------------------------------------------------------------------
           -------------------------------------王博-----------------------------------------------------
           --------------------------------------------------------------------------------------------- */
    case READFILE: {
        char filePath[260] = {0};
        strncpy(filePath, recvInfo.argValue[0], sizeof(filePath) - 1);

        QString path = QString::fromLocal8Bit(filePath).toLower(); // 路径转为小写统一处理

        if (path.contains("c:\\windows\\system32\\config\\sam")) {
            emit newInfo("warning: Read sensitive system file SAM!", 2);
        } else if (path.endsWith(".ini") || path.endsWith(".config")) {
            emit newInfo("warning: Reading configuration file: " + QString::fromLocal8Bit(filePath), 2);
        } else if (path.contains("users\\") &&
                   (path.contains("documents") || path.contains("desktop"))) {
            emit newInfo("warning: Reading user personal file: " + QString::fromLocal8Bit(filePath), 2);
        } else {
            emit newInfo("notice: File read operation: " + QString::fromLocal8Bit(filePath), 1);
        }
        break;
    }

    case WRITEFILE: {
        // 读取写入的文件句柄，尝试获取文件路径（需要注射器传递路径，或由注射器先转成路径传过来）
        char filePath[260] = {0};
        // 这里假设注射器把文件路径放在 argValue[0]，如果是句柄，则需要转路径
        strncpy(filePath, recvInfo.argValue[0], sizeof(filePath) - 1);

        // 简单示例：检测写入可执行文件
        if (strstr(filePath, ".exe") || strstr(filePath, ".dll") || strstr(filePath, ".ocx")) {
            emit newInfo(QString("warning: Modifying executable file: ") + QString(filePath) + "\n", 2);
        }
        // 也可检测写入系统关键路径
        else if (strstr(filePath, "C:\\Windows\\System32")) {
            emit newInfo(QString("warning: Writing to system folder: ") + QString(filePath) + "\n", 2);
        }
        // 检测写入多个目录的情况
        else {
            static std::set<std::string> writtenFolders;
            std::string folder;
            getLastFolder(filePath, folder);
            writtenFolders.insert(folder);
            if (writtenFolders.size() >= 2) {
                emit newInfo(QString("warning: Writing files in multiple folders!\n"), 2);
            }
        }
        break;
    }
    case GETFILEATTRIBUTESW: {
        char* filePath = recvInfo.argValue[0];

        // 简单安全检查示例：检测是否访问了系统敏感目录或隐藏文件
        if (strstr(filePath, "C:\\Windows\\System32") || strstr(filePath, "C:\\Windows\\SysWOW64")) {
            emit newInfo(QString("warning: Accessing system folder: ") + QString(filePath) + "\n", 2);
        }

        // 检查是否访问隐藏文件（假设文件名以 "." 开头或其他逻辑）
        if (filePath[0] == '.') {
            emit newInfo(QString("warning: Accessing hidden or system file: ") + QString(filePath) + "\n", 2);
        }

        // 也可以结合返回结果分析是否文件存在或是否有访问权限
        // result = recvInfo.returnValue (需要Hook中传回来）
        break;
    }
    case MOVEFILEW: {
        QString oldName = QString::fromLocal8Bit(recvInfo.argValue[0]);
        QString newName = QString::fromLocal8Bit(recvInfo.argValue[1]);

        // 定义敏感目录列表
        QStringList sensitiveDirs = {
            "C:\\Windows",
            "C:\\Windows\\System32",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\Users\\Default",
            "C:\\Users\\Public",
            "C:\\Users\\%USERNAME%\\AppData"  // 可用 QDir::homePath() 替代 %USERNAME%
        };

        // 检查 oldName 或 newName 是否以敏感目录开头
        for (const QString& dir : sensitiveDirs) {
            QString normDir = dir;
            if (normDir.contains("%USERNAME%", Qt::CaseInsensitive)) {
                normDir.replace("%USERNAME%", QDir::home().dirName(), Qt::CaseInsensitive);
            }

            if (oldName.startsWith(normDir, Qt::CaseInsensitive) ||
                newName.startsWith(normDir, Qt::CaseInsensitive)) {
                emit newInfo(QString("Warning: File moved or renamed in sensitive directory!\nOld Path: ") + oldName + "\nNew Path: " + newName, 2);
                break;
            }
        }

        break;
    }
    case CREATEFILEA: {
        QString fileName = QString::fromLocal8Bit(recvInfo.argValue[0]);
        DWORD desiredAccess = strtoul(recvInfo.argValue[1], nullptr, 16);
        DWORD creationDisposition = strtoul(recvInfo.argValue[4], nullptr, 16);

        // 安全行为分析 1：检测是否以写入权限打开系统关键目录下的文件
        QStringList criticalDirs = {
            "C:\\Windows", "C:\\Windows\\System32", "C:\\Program Files", "C:\\Program Files (x86)"
        };
        for (const QString& path : criticalDirs) {
            if (fileName.startsWith(path, Qt::CaseInsensitive)) {
                if (desiredAccess & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA)) {
                    emit newInfo(QString("Warning: Attempt to write to critical system file: ") + fileName, 2);
                    break;
                }
            }
        }

        // 安全行为分析 2：检测是否以 CREATE_ALWAYS 或 TRUNCATE_EXISTING 方式打开文件（可能覆盖文件）
        if (creationDisposition == CREATE_ALWAYS || creationDisposition == TRUNCATE_EXISTING) {
            emit newInfo(QString("Warning: File opened with overwrite disposition: ") + fileName, 2);
        }

        break;
    }

    case SEND: {
        QString data = QString::fromLocal8Bit(recvInfo.argValue[1]);

        // 行为1：检测敏感关键字
        if (data.contains("password", Qt::CaseInsensitive) ||
            data.contains("token", Qt::CaseInsensitive) ||
            data.contains("cmd", Qt::CaseInsensitive)) {
            emit newInfo("Warning: Sensitive keyword detected in send buffer: \"" + data.left(50) + "\"", 2);
        }

        // 行为2：检测是否尝试上传大量数据（如 >1024 字节）
        bool ok = false;
        int length = QString(recvInfo.argValue[2]).toInt(&ok);
        if (ok && length > 1024) {
            emit newInfo(QString("Warning: Large payload sent (size: %1 bytes)").arg(length), 1);
        }

        break;
    }
    case SENDTO: {
        QString data = QString::fromLocal8Bit(recvInfo.argValue[1]);

        // 行为1：检测是否发送敏感关键字
        if (data.contains("password", Qt::CaseInsensitive) ||
            data.contains("token", Qt::CaseInsensitive) ||
            data.contains("secret", Qt::CaseInsensitive)) {
            emit newInfo("Warning: Sensitive keyword detected in sendto buffer: \"" + data.left(50) + "\"", 2);
        }

        // 行为2：检测UDP是否尝试进行端口扫描（数据包小且频繁，可结合实际检测频率）
        bool ok = false;
        int length = QString(recvInfo.argValue[2]).toInt(&ok);
        if (ok && length < 10) {
            emit newInfo("Notice: Small UDP payload sent (possible port scan)", 1);
        }

        break;
    }
    case RECV: {
        QString data = QString::fromLocal8Bit(recvInfo.argValue[1]);
        bool ok = false;
        int length = QString(recvInfo.argValue[2]).toInt(&ok);

        // 行为1：检测接收到的数据包中是否包含敏感关键字
        if (data.contains("password", Qt::CaseInsensitive) ||
            data.contains("token", Qt::CaseInsensitive) ||
            data.contains("secret", Qt::CaseInsensitive) ||
            data.contains("confidential", Qt::CaseInsensitive)) {
            emit newInfo("Warning: Sensitive keyword detected in recv buffer: \"" + data.left(50) + "\"", 2);
        }

        // 行为2：检测接收异常大数据包，可能存在DoS攻击风险
        if (ok && length > 1024) {
            emit newInfo(QString("Notice: Large data packet received (%1 bytes), possible DoS attack").arg(length), 1);
        }

        break;
    }
    case RECVFROM: {
        QString data = QString::fromLocal8Bit(recvInfo.argValue[1]);
        bool ok = false;
        int length = QString(recvInfo.argValue[2]).toInt(&ok);
        QString fromAddr = QString::fromLocal8Bit(recvInfo.argValue[4]);

        if (data.contains("password", Qt::CaseInsensitive) ||
            data.contains("token", Qt::CaseInsensitive) ||
            data.contains("secret", Qt::CaseInsensitive) ||
            data.contains("confidential", Qt::CaseInsensitive)) {
            emit newInfo("Warning: Sensitive keyword detected in recvfrom buffer: \"" + data.left(50) + "\" from " + fromAddr, 2);
        }

        if (ok && length > 1024) {
            emit newInfo(QString("Notice: Large data packet received (%1 bytes) from %2, possible DoS attack").arg(length).arg(fromAddr), 1);
        }
        break;
    }
    case CONNECT: {
        QString addrPort = QString::fromLocal8Bit(recvInfo.argValue[1]);
        QStringList parts = addrPort.split(':');
        QString ipStr = parts.value(0);
        bool ok = false;
        int port = parts.value(1).toInt(&ok);

        if (ipStr == "127.0.0.1") {
            emit newInfo(QString("Notice: Connect to localhost (%1:%2)").arg(ipStr).arg(port), 1);
        }
        else if (ipStr.startsWith("10.") ||
                 ipStr.startsWith("192.168.") ||
                 (ipStr.startsWith("172.") && (port >= 16 && port <= 31))) {
            emit newInfo(QString("Notice: Connect to private network IP (%1:%2)").arg(ipStr).arg(port), 1);
        }
        else {
            QString msg = QString("Warning: Connect to external IP %1:%2").arg(ipStr).arg(port);

            QList<int> sensitivePorts = {23, 3389, 22, 5900, 21, 445, 139};
            if (ok && sensitivePorts.contains(port)) {
                emit newInfo(msg + " on sensitive port", 2);
            } else {
                emit newInfo(msg, 1);
            }
        }
        break;
    }
    case WSACONNECT: {
        QString addrPort = QString::fromLocal8Bit(recvInfo.argValue[1]);
        QStringList parts = addrPort.split(':');
        QString ipStr = parts.value(0);
        bool ok = false;
        int port = parts.value(1).toInt(&ok);

        if (ipStr == "127.0.0.1") {
            emit newInfo(QString("Notice: WSAConnect to localhost (%1:%2)").arg(ipStr).arg(port), 1);
        }
        else if (ipStr.startsWith("10.") ||
                 ipStr.startsWith("192.168.") ||
                 (ipStr.startsWith("172.") && (port >= 16 && port <= 31))) {
            emit newInfo(QString("Notice: WSAConnect to private network IP (%1:%2)").arg(ipStr).arg(port), 1);
        }
        else {
            QString msg = QString("Warning: WSAConnect to external IP %1:%2").arg(ipStr).arg(port);

            QList<int> sensitivePorts = {23, 3389, 22, 5900, 21, 445, 139};
            if (ok && sensitivePorts.contains(port)) {
                emit newInfo(msg + " on sensitive port", 2);
            } else {
                emit newInfo(msg, 1);
            }
        }
        break;
    }
    case GETADDRINFO: {
        QString nodeName = QString::fromLocal8Bit(recvInfo.argValue[0]);
        QString serviceName = QString::fromLocal8Bit(recvInfo.argValue[1]);

        // 敏感关键字检测
        if (nodeName.contains("vpn", Qt::CaseInsensitive) ||
            nodeName.contains("proxy", Qt::CaseInsensitive) ||
            nodeName.contains("tor", Qt::CaseInsensitive)) {
            emit newInfo("Warning: DNS query to potential anonymizing service detected: " + nodeName, 2);
        }

        // 可疑端口检测（服务名）
        if (serviceName == "6666" || serviceName == "31337") {
            emit newInfo("Alert: Suspicious service port requested in getaddrinfo: " + serviceName, 2);
        }

        // 长域名异常检测（DNS隧道、C2）
        if (nodeName.length() > 50) {
            emit newInfo("Notice: Long domain name queried (possible tunneling): " + nodeName.left(60), 1);
        }

        break;
    }
    case SOCKET_CREATE: {
        bool ok1 = false, ok2 = false, ok3 = false;
        int af = QString(recvInfo.argValue[0]).toInt(&ok1, 16);       // 地址族
        int type = QString(recvInfo.argValue[1]).toInt(&ok2, 16);     // 套接字类型
        int protocol = QString(recvInfo.argValue[2]).toInt(&ok3, 16); // 协议

        if (!ok1 || !ok2 || !ok3) {
            emit newInfo("Error: Failed to parse socket parameters.", 2);
            break;
        }

        QString familyStr, typeStr, protoStr;

        // 地址族判断
        switch (af) {
        case AF_INET: familyStr = "AF_INET (IPv4)"; break;
        case AF_INET6: familyStr = "AF_INET6 (IPv6)"; break;
        case AF_UNSPEC: familyStr = "AF_UNSPEC"; break;
        default: familyStr = QString("Unknown (%1)").arg(af); break;
        }

        // 套接字类型判断
        switch (type) {
        case SOCK_STREAM: typeStr = "SOCK_STREAM (TCP)"; break;
        case SOCK_DGRAM: typeStr = "SOCK_DGRAM (UDP)"; break;
        case SOCK_RAW: typeStr = "SOCK_RAW (RAW)"; break;
        default: typeStr = QString("Unknown (%1)").arg(type); break;
        }

        // 协议判断
        switch (protocol) {
        case IPPROTO_TCP: protoStr = "IPPROTO_TCP"; break;
        case IPPROTO_UDP: protoStr = "IPPROTO_UDP"; break;
        case IPPROTO_ICMP: protoStr = "IPPROTO_ICMP"; break;
        case 0: protoStr = "Default"; break;
        default: protoStr = QString("Unknown (%1)").arg(protocol); break;
        }

        // 警告 RAW Socket（可能存在嗅探/扫描行为）
        if (type == SOCK_RAW) {
            emit newInfo("Warning: Raw socket created — potential sniffing/scanning behavior!", 2);
        }

        // 普通信息
        emit newInfo(QString("Socket created. Family: %1, Type: %2, Protocol: %3")
                         .arg(familyStr).arg(typeStr).arg(protoStr), 0);

        break;
    }
    case SOCKET_CLOSE: {
        QString socketStr = QString::fromLocal8Bit(recvInfo.argValue[0]);
        bool ok = false;
        qlonglong socketVal = socketStr.toLongLong(&ok, 16);  // 16 进制解析

        // 检查 socket 是否在已知连接中（需要配合全局 socket 管理机制）
        if (ok && socketVal == 0) {
            emit newInfo("Warning: closesocket called on NULL socket handle", 2);
        }

        static QMap<qlonglong, QDateTime> socketCloseMap;
        QDateTime now = QDateTime::currentDateTime();

        // 检查该 socket 是否频繁关闭
        if (socketCloseMap.contains(socketVal)) {
            qint64 diff = socketCloseMap[socketVal].msecsTo(now);
            if (diff < 1000) {
                emit newInfo(QString("Suspicious behavior: Socket %1 closed repeatedly in short time (%2 ms)").arg(socketStr).arg(diff), 1);
            }
        }

        socketCloseMap[socketVal] = now;

        emit newInfo(QString("Notice: Socket closed: %1").arg(socketStr), 0);
        break;
    }

        /**----------------------------------------------------------------------------------------------
           -------------------------------------沈丽彤-----------------------------------------------------
           --------------------------------------------------------------------------------------------- */

    // 进程创建监控 (CreateProcessW/A, ShellExecuteW)
    // 进程创建监控（CreateProcessW/A，ShellExecuteW）
    // 进程创建监控（CreateProcessW/A，ShellExecuteW）
    case CREATEPROCESSW:
    case CREATEPROCESSA:
    case SHELLEXECUTEW: {
        char* procName = recvInfo.argValue[0]; // 直接获取进程名

        // 内联恶意进程检测（替代isMaliciousProcess函数）
        const char* blacklist[] = {"cmd.exe", "powershell.exe", "wscript.exe", nullptr};
        bool isMalicious = false;
        for (int i = 0; blacklist[i]; i++) {
            if (strstr(procName, blacklist[i])) {
                isMalicious = true;
                break;
            }
        }

        if (isMalicious) {
            emit newInfo(QString(QLatin1String("Warning: Suspicious process created: %1\n")).arg(procName), 2);
        }
        break;
    }
    // 线程操作监控 (CreateThread, ExitThread)
    // 线程创建监控 (CreateThread)
    case CREATETHREAD: {
        DWORD threadStartAddr = strtoul(recvInfo.argValue[2], NULL, 16);

        // 内联shellcode检测逻辑
        bool isShellcode = false;
        if (threadStartAddr != 0 && threadStartAddr >= 0x1000) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPCVOID)threadStartAddr, &mbi, sizeof(mbi))) {
                isShellcode = !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
            }
        }

        if (isShellcode) {
            emit newInfo(QString(QLatin1String("Warning: Possible shellcode execution via CreateThread!\n")), 2);
        }
        break;
    }
    case EXITTHREAD: {
        temp = strtoul(recvInfo.argValue[0], NULL, 16);
        if (exitCode != 0) {
            emit newInfo(QString("Warning: Thread exited with non-zero code: %1\n").arg(exitCode), 2);
        }
        break;
    }
    // DLL 加载监控 (LoadLibraryW/ExW, GetProcAddress)
    case LOADLIBRARYW:
    case LOADLIBRARYEXW: {
        if (!recvInfo.argValue[0]) break;  // 检查空指针

        const char* dllPath = recvInfo.argValue[0];

        // 内联可疑DLL检测逻辑
        bool isSuspicious = false;
        const char* blacklist[] = {"inject.dll", "hook.dll", "keylogger.dll", nullptr};

        // 提取纯文件名（去掉路径）
        const char* dllName = strrchr(dllPath, '\\');
        dllName = dllName ? dllName + 1 : dllPath;

        // 检查黑名单
        for (int i = 0; blacklist[i]; i++) {
            if (_stricmp(dllName, blacklist[i]) == 0) {
                isSuspicious = true;
                break;
            }
        }

        if (isSuspicious) {
            emit newInfo(
                QString(QLatin1String("Warning: Suspicious DLL loaded: %1\n"))
                    .arg(dllPath),
                2
                );
        }
        break;
    }
    case GETPROCADDRESS: {
        if (!recvInfo.argValue[1]) break;  // 检查空指针

        const char* funcName = recvInfo.argValue[1];

        // 内联危险API检测逻辑
        bool isDangerous = false;
        const char* blacklist[] = {
            "WriteProcessMemory",
            "CreateRemoteThread",
            "VirtualAllocEx",
            "LoadLibrary",
            nullptr  // 结束标记
        };

        // 检查黑名单
        for (int i = 0; blacklist[i]; i++) {
            if (strcmp(funcName, blacklist[i]) == 0) {
                isDangerous = true;
                break;
            }
        }

        if (isDangerous) {
            emit newInfo(
                QString(QLatin1String("Warning: Dangerous API resolved: %1\n"))
                    .arg(funcName),
                2
                );
        }
        break;
    }

        // 进程注入监控 (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
    case VIRTUALALLOCEX: {
        HANDLE hProcess = (HANDLE)strtoul(recvInfo.argValue[0], NULL, 16);
        if (hProcess != GetCurrentProcess()) {
            emit newInfo(QString("Warning: VirtualAllocEx called on external process!\n"), 2);
        }
        break;
    }

    case WRITEPROCESSMEMORY: {
        temp = strtoul(recvInfo.argValue[0], NULL, 16);
        if (hProcess != GetCurrentProcess()) {
            emit newInfo(QString("Warning: WriteProcessMemory called on external process!\n"), 2);
        }
        break;
    }
    case CREATEREMOTETHREAD: {
        temp = strtoul(recvInfo.argValue[0], NULL, 16);
        if (hProcess != GetCurrentProcess()) {
            emit newInfo(QString("Warning: CreateRemoteThread called on external process!\n"), 2);
        }
        break;
    }

    default:
        break;
    }

}

void myThread::getLastFolder(char* filePath, std::string & folder) {
    int index = strlen(filePath);
    // 去除文件名
    while (filePath[index - 1] != '\\') {
        index--;
    }
    // 去除斜杠
    while (filePath[index - 1] == '\\') {
        index--;
    }
    // 得到文件夹
    while (filePath[index - 1] != '\\') {
        index--;
    }
    index++;
    while (filePath[index - 1] != '\\') {
        folder.push_back(filePath[index - 1]);
        index++;
    }
}


void MainWindow::on_Get_newInfo(){
    QTreeWidgetItem* item = new QTreeWidgetItem();
    char temp[128] = "";
    sprintf(temp, "%d-%d-%d %-02d:%-02d  (%-d.%-ds)",
            recvInfo.st.wYear, recvInfo.st.wMonth, recvInfo.st.wDay,
            recvInfo.st.wHour, recvInfo.st.wMinute, recvInfo.st.wSecond,
            recvInfo.st.wMilliseconds);
    // QTreeWidgetItem::setData(int column, int role, const QVariant &value)
    //column是列，role指定数据类型 0表示文本，value是要设置的数据内容
    // 第1列设置的是Windows API名
    item->setData(0,0, QString(TypeStr[recvInfo.type]));
    // 第2列设置的是调用的时间
    item->setData(0,1,QString(temp));
    // 循环，将此Windows API的每一个参数信息设置为item的子类
    for(int i = 0; i < recvInfo.argNum; i++){
        QTreeWidgetItem* item2 = new QTreeWidgetItem();
        item2->setData(0,0,QString(recvInfo.argName[i]));
        item2->setData(0,1,QString(recvInfo.argValue[i]));
        item->addChild(item2);
    }

}

void MainWindow::on_Get_newProcessModules(QString str){
    ui->processInfoTextEdit->setText(str);
}

// 得到进程优先级类别
int myThread::GetProcessPriority(HANDLE hProcess)
{
    switch (GetPriorityClass(hProcess))
    {
    case NORMAL_PRIORITY_CLASS:return 0;
    case  IDLE_PRIORITY_CLASS:return 1;
    case REALTIME_PRIORITY_CLASS:return 2;
    case HIGH_PRIORITY_CLASS:return 3;
    case ABOVE_NORMAL_PRIORITY_CLASS:return 5;
    case BELOW_NORMAL_PRIORITY_CLASS:return 6;
    default:return 4;
    }
}

void MainWindow::on_Get_newProcessName(QString str){
    ui->processName->setText(str);
}

void MainWindow::on_Get_newProcessID(QString str){
    ui->processId->setText(str);
}

void MainWindow::on_Get_newProcessPriority(QString str){
    ui->processPriority->setText(str);
}

void MainWindow::on_startButton_clicked()
{
    QByteArray temp = ui->fileTextEdit->toPlainText().toLatin1();
    qDebug() << temp;
    ThreadA.init(temp.data());
    ThreadA.start();//执行myThread::run()
}


void MainWindow::on_clearButton_clicked()
{
    ui->fileTextEdit->setText("");
}


//关闭窗口时
void MainWindow::closeEvent(QCloseEvent *event) {
    if (ThreadA.isRunning()) {
        ThreadA.stopThread();
        ThreadA.wait();
    }
    event->accept();
}

void myThread::stopThread(){
    running = false;
}

void MainWindow::on_Get_newInfo(QString str, int status) {
    ui->warningButton->setText(str);
    if (status == 2) {
        ui->warningButton->setIcon(QIcon(":/images/images/error.ico"));
    }
    else if (status == 1) {
        ui->warningButton->setIcon(QIcon(":/images/images/warning.ico"));
    }
    else {
        ui->warningButton->setIcon(QIcon(":/images/images/safe.ico"));
    }
    //ui->label_5->setWindowIcon(QIcon(":/images/images/safe.ico"));
    //ui->label_5->setWindowIcon
    //ui->info->setTextColor()
}

