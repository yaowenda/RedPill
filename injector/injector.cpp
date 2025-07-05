#include <windows.h>
#include <iostream>
#include <string>
#include<detours.h>
#include<thread>
using namespace std;
int main(int argc, char* argv[]) {
	//// 防止自己注入自己
	//if (strstr(argv[0], "injector")) {
	//	printf("自己注入了自己，即将退出");
	//	return 0;
	//}
	printf("[injector] 启动 injector 程序\n");

	//wchar_t是宽字符类型
	wchar_t fileName[256] = L"";
	//该Windows API函数 用于将多字节字符串（通常是ANSI编码）转换为宽字符串（Unicode）
	MultiByteToWideChar(CP_ACP, 0, argv[0], strlen(argv[0]), fileName, sizeof(fileName));
	wprintf(L"[injector] 当前路径: %s\n", fileName);

	STARTUPINFO si; // Windows结构体，包含新进程的启动信息，在创建新进程时使用
	PROCESS_INFORMATION pi; //Windows结构体，用于在成功创建新进程后返回新进程和线程的信息
	ZeroMemory(&si, sizeof(STARTUPINFO)); //将 STARTUPINFO 结构体 si 的所有成员都初始化为零
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION)); //将 PROCESS_INFORMATION 结构体 pi 的所有成员初始化为零。

	// cb是STARTUPINFO结构体的第一个成员，必须设置为结构体自身的大小，所以这里设置一下
	si.cb = sizeof(STARTUPINFO);
	// 文件夹路径
	// MAX_PATH 是一个常数，通常定义为260，代表Windows系统文件路径的最大长度，加1是为了容纳\0
	WCHAR DirPath[MAX_PATH + 1];
	// ******需要修改部分**********
	//wcscpy_s(DirPath, MAX_PATH, L"C:\\Users\\86151\\Desktop\\PFSafetyGuard\\PFSafetyGuard\\PFDLL\\x64\\Release");	// dll文件夹
	wcscpy_s(DirPath, MAX_PATH, L"D:\\RedPill\\hook\\x64\\Release");

		// 文件路径
	//char DLLPath[MAX_PATH + 1] = "C:\\Users\\86151\\Desktop\\PFSafetyGuard\\PFSafetyGuard\\PFDLL\\x64\\Release\\PFDLL.dll"; // dll的地址
	char DLLPath[MAX_PATH + 1] = "D:\\RedPill\\hook\\x64\\Release\\hook.dll"; // dll的地址
	// ******需要修改部分**********
	// 要注入DLL的EXE路径初始化
	WCHAR EXE[MAX_PATH + 1] = { 0 };
	
	
	wcscpy_s(EXE, MAX_PATH, L"D:\\RedPill\\AppTest\\x64\\Release\\AppTest.exe");
	//wcscpy_s(EXE, MAX_PATH, L"C:\\Users\\86151\\Desktop\\RedPill\\AppTest\\x64\\Release\\AppTest.exe");
	//wcscpy_s(EXE, MAX_PATH, L"E:\\record\\6th\\softwareSecurity\\code\\heapCreateAndDestory\\Debug\\heapCreateAndDestory.exe"); // HeapCreate & HeapDestory
	//wcscpy_s(EXE, MAX_PATH, fileName); // HeapCreate & HeapDestory

	wprintf(L"[injector] 准备注入到: %s\n", EXE);
	printf("[injector] DLL路径: %s\n", DLLPath);

	printf("[injector] 开始调用 DetourCreateProcessWithDllEx...\n");

	// DetourCreateProcessWithDllEx 函数用于创建一个新进程并注入DLL
	if (DetourCreateProcessWithDllEx(EXE, NULL, NULL, NULL, TRUE,
		CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED, NULL, DirPath,
		&si, &pi, DLLPath, NULL)) {

		printf("[injector] 创建进程并注入 DLL 成功！\n");

		// 恢复线程
		ResumeThread(pi.hThread);
		printf("[injector] 目标进程线程已恢复\n");

		WaitForSingleObject(pi.hProcess, INFINITE);
		printf("[injector] 目标进程已退出\n");
	}
	else {
		char error[100];
		sprintf_s(error, sizeof(error), "%d", GetLastError());
		printf("[injector] 注入失败，错误代码: %lu\n", error);
	}
	return 0;
}
