#include <windows.h>
#include <iostream>
#include <string>
#include<detours.h>
#include<thread>
using namespace std;
int main(int argc, char* argv[]) {
	//// ��ֹ�Լ�ע���Լ�
	//if (strstr(argv[0], "injector")) {
	//	printf("�Լ�ע�����Լ��������˳�");
	//	return 0;
	//}
	printf("[injector] ���� injector ����\n");

	//wchar_t�ǿ��ַ�����
	wchar_t fileName[256] = L"";
	//��Windows API���� ���ڽ����ֽ��ַ�����ͨ����ANSI���룩ת��Ϊ���ַ�����Unicode��
	MultiByteToWideChar(CP_ACP, 0, argv[0], strlen(argv[0]), fileName, sizeof(fileName));
	wprintf(L"[injector] ��ǰ·��: %s\n", fileName);

	STARTUPINFO si; // Windows�ṹ�壬�����½��̵�������Ϣ���ڴ����½���ʱʹ��
	PROCESS_INFORMATION pi; //Windows�ṹ�壬�����ڳɹ������½��̺󷵻��½��̺��̵߳���Ϣ
	ZeroMemory(&si, sizeof(STARTUPINFO)); //�� STARTUPINFO �ṹ�� si �����г�Ա����ʼ��Ϊ��
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION)); //�� PROCESS_INFORMATION �ṹ�� pi �����г�Ա��ʼ��Ϊ�㡣

	// cb��STARTUPINFO�ṹ��ĵ�һ����Ա����������Ϊ�ṹ������Ĵ�С��������������һ��
	si.cb = sizeof(STARTUPINFO);
	// �ļ���·��
	// MAX_PATH ��һ��������ͨ������Ϊ260������Windowsϵͳ�ļ�·������󳤶ȣ���1��Ϊ������\0
	WCHAR DirPath[MAX_PATH + 1];
	// ******��Ҫ�޸Ĳ���**********
	//wcscpy_s(DirPath, MAX_PATH, L"C:\\Users\\86151\\Desktop\\PFSafetyGuard\\PFSafetyGuard\\PFDLL\\x64\\Release");	// dll�ļ���
	wcscpy_s(DirPath, MAX_PATH, L"D:\\RedPill\\hook\\x64\\Release");

		// �ļ�·��
	//char DLLPath[MAX_PATH + 1] = "C:\\Users\\86151\\Desktop\\PFSafetyGuard\\PFSafetyGuard\\PFDLL\\x64\\Release\\PFDLL.dll"; // dll�ĵ�ַ
	char DLLPath[MAX_PATH + 1] = "D:\\RedPill\\hook\\x64\\Release\\hook.dll"; // dll�ĵ�ַ
	// ******��Ҫ�޸Ĳ���**********
	// Ҫע��DLL��EXE·����ʼ��
	WCHAR EXE[MAX_PATH + 1] = { 0 };
	
	
	wcscpy_s(EXE, MAX_PATH, L"D:\\RedPill\\AppTest\\x64\\Release\\AppTest.exe");
	//wcscpy_s(EXE, MAX_PATH, L"C:\\Users\\86151\\Desktop\\RedPill\\AppTest\\x64\\Release\\AppTest.exe");
	//wcscpy_s(EXE, MAX_PATH, L"E:\\record\\6th\\softwareSecurity\\code\\heapCreateAndDestory\\Debug\\heapCreateAndDestory.exe"); // HeapCreate & HeapDestory
	//wcscpy_s(EXE, MAX_PATH, fileName); // HeapCreate & HeapDestory

	wprintf(L"[injector] ׼��ע�뵽: %s\n", EXE);
	printf("[injector] DLL·��: %s\n", DLLPath);

	printf("[injector] ��ʼ���� DetourCreateProcessWithDllEx...\n");

	// DetourCreateProcessWithDllEx �������ڴ���һ���½��̲�ע��DLL
	if (DetourCreateProcessWithDllEx(EXE, NULL, NULL, NULL, TRUE,
		CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED, NULL, DirPath,
		&si, &pi, DLLPath, NULL)) {

		printf("[injector] �������̲�ע�� DLL �ɹ���\n");

		// �ָ��߳�
		ResumeThread(pi.hThread);
		printf("[injector] Ŀ������߳��ѻָ�\n");

		WaitForSingleObject(pi.hProcess, INFINITE);
		printf("[injector] Ŀ��������˳�\n");
	}
	else {
		char error[100];
		sprintf_s(error, sizeof(error), "%d", GetLastError());
		printf("[injector] ע��ʧ�ܣ��������: %lu\n", error);
	}
	return 0;
}
