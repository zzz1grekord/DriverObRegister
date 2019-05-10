#pragma once
#include "Misc.h"
#include "Service.h"
class CService;
CService *svc = new CService();
class CDriver {
private:
	HANDLE m_hDriverDevice = NULL;
	DWORD ReturetLength = 0;
public:
	CDriver() {

	}

	void DriverLoad(char* Name) {

		char PatchName[200] = "";

		GetFullPathName(Name, 200, PatchName, NULL);
		svc->InitSvc(PatchName, Name, Name, SERVICE_DEMAND_START);

		if (svc->CreateSvc() == SVC_OK) {
		//	MessageBox(NULL, "Create", " ", MB_OK);
			Console::Success("Service create\n");
		}
		else {
		//	MessageBox(NULL, "Err Create", " ", MB_OK);
			Console::Error("Service not createded\n\n");
		}


		if (svc->StartSvc() == SVC_OK) {
		//	MessageBox(NULL, "Start", " ", MB_OK);
			Console::Success("DriverEntry call\n");
		}
		else {
		//	MessageBox(NULL, " Err Start", " ", MB_OK);
			Console::Error("DriverEntry not called\n\n");
		}
	}
	void UnloadDriver() {
		if (svc->StopSvc() == SVC_OK) {

		}
		else {

		}

		if (svc->UnloadSvc() == SVC_OK) {

		}
		else {

		}
	}
	void OpenDriverDevice(LPCSTR DeviceName) {
		m_hDriverDevice = CreateFile(DeviceName, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);

		if (m_hDriverDevice == INVALID_HANDLE_VALUE) {

			Console::Error("Invalid driver device\n");
			UnloadDriver();
			system("sc queryex ObRegister.sys");
			system("pause > null");
			TerminateProcess(GetCurrentProcess(), 1337);
		}
	}
	void SetupCallback(DWORD PID) {
		int pid = (int)PID;
		DeviceIoControl(m_hDriverDevice, IOCTL_SETUPOBJECTPRECALLBACK,
			&pid, sizeof(pid),
			//&test, 4,
			0, 0,
			&ReturetLength, NULL);
	}
	void FreeProcFilter() {
		DeviceIoControl(m_hDriverDevice, IOCTL_FREEPROCFILTERCALLBACK,
			0, 0,
			0, 0,
			&ReturetLength, NULL);
	}
	void RequestToDriver(DWORD ioctl, LPVOID In, DWORD InSize, LPVOID Out, DWORD OutSize, LPDWORD ReturnLength) {
		DeviceIoControl(m_hDriverDevice, ioctl, In, InSize, Out, OutSize, ReturnLength, 0);
	}
	void WriteProcessMem(int PID, LPVOID InBuffer, int Size, DWORD TargetAdr) {

		if (PID <= 1) {
			MessageBox(0, "PID error", "WriteProcessMem", MB_ICONERROR | MB_OK);
			return;

		}
	
		RWRITE_PARAMS paramsToRW;
		DWORD dwA = (DWORD)TargetAdr;
		paramsToRW.PID = PID;
		paramsToRW.Size = Size;
		memcpy(&paramsToRW.SourceA, InBuffer, sizeof(InBuffer));
		memcpy(&paramsToRW.TargetA, &dwA, sizeof(dwA));
		//paramsToRW.Size = 4;


		RequestToDriver(IOCTL_WRITEMEMORY, &paramsToRW, sizeof(paramsToRW), 0, 0, &ReturetLength);
	}
	void ReadProcessMem(int PID, LPVOID OutBuffer, int Size, DWORD TargeAdr) {


		if (PID <= 1) {
			MessageBox(0, "PID error", "ReadProcessMem", MB_ICONERROR | MB_OK);
			return;

		}

		READ_PARAMS reader;
		reader.PID = PID;
		reader.Size = Size;
		DWORD ta = (DWORD)TargeAdr;
		memcpy(&reader.SourceA, &ta, sizeof(ta));
		RequestToDriver(IOCTL_READMEMORY, &reader, sizeof(reader), OutBuffer, Size, &ReturetLength);
	}
	void VirtualAlloc(int PID, DWORD TargetAdr, int Size, LPVOID AlloatedAdr) {

		if (PID <= 1) {
			MessageBox(0, "PID error", "VirtualAlloc", MB_ICONERROR | MB_OK);
			return;

		}

		VIRTUAL_ALLOC_MEM_PARAMS vall;

		vall.PID = PID;
		vall.Size = Size;
		DWORD ta = (DWORD)TargetAdr;
		memcpy(&vall.TargetA, &ta, sizeof(ta));
		RequestToDriver(IOCTL_ALLOCMEMORY, &vall, sizeof(vall), AlloatedAdr, sizeof(DWORD32), &ReturetLength);

	}
	void Destroyer() {
		CloseHandle(m_hDriverDevice);
	}
	
	~CDriver() {
		Destroyer();
		UnloadDriver();
		Sleep(200);
		system("sc queryex ObRegister.sys");
	}
};
extern CDriver* g_pDrv;