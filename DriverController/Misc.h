#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include "Console.hpp"
#include <sstream>
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

#define IOCTL_HIDEPROCESS  CTL_CODE(FILE_DEVICE_myDrv,  \
                                          FIRST_IOCTL_INDEX + 108,  \
                                          METHOD_BUFFERED,       \
                                          FILE_ANY_ACCESS)

typedef struct _VIRTUAL_ALLOC_MEM_PARAMS {
	int PID;
	int Size;
	PVOID TargetA;

} VIRTUAL_ALLOC_MEM_PARAMS, *PVIRTUAL_ALLOC_MEM_PARAMS;

typedef struct _memadactr {
	int i;
	int b;
} memadactr, *pmemadactr;

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
