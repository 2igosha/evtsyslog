/*
Copyright (c) 2020, 2igosha

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

This simple service forwards all Windows event log events to a remote syslog server via UDP

To install to %APPDATA%\Local\Programs and create a service: 
	evtsyslog.exe install

Settings are read on startup from registry:
	HKLM\Evtsyslog
		REG_SZ SyslogHost - remote host name or IP address, default none
		REG_SZ SyslogPort - port number, default 514
*/

#include <ws2tcpip.h>
#include <Windows.h>
#include <winevt.h>
#include <vector>
#include <string>
#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#include <shlobj_core.h>

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

const std::wstring regKeyName = L"SOFTWARE\\Evtsyslog";

constexpr unsigned PORT_NUMBER_DEFAULT = 514;

// UDP destination IP, big endian
uint32_t syslogIP = INADDR_NONE;
// UDP destination port, big endian
uint16_t syslogPort = htons(PORT_NUMBER_DEFAULT);

bool ReadRegistryString(HKEY key, const std::wstring valueName, std::wstring* result) {
	DWORD numToRead = 0;
	DWORD type = 0;
	if (RegQueryValueExW(key, valueName.c_str(), NULL, &type, NULL, &numToRead) != ERROR_SUCCESS) {
		return false;
	}
	if (type != REG_SZ) {
		return false;
	}
	std::vector<WCHAR> buffer((size_t)(numToRead/sizeof(WCHAR) + 1));
	if (RegQueryValueExW(key, valueName.c_str(), NULL, &type, reinterpret_cast<LPBYTE>(&buffer[0]), &numToRead) != ERROR_SUCCESS) {
		return false;
	}
	if (type != REG_SZ) {
		return false;
	}
	buffer[buffer.size() - 1] = 0; // guarantee null-termination
	result->assign(buffer.begin(), buffer.end());
	return true;
}

bool LoadSettingsFromRegistry() {
	HKEY key;
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, regKeyName.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) != ERROR_SUCCESS) {
		return false;
	}
	bool result = true;
	std::wstring tmp;
	if (!ReadRegistryString(key, L"SyslogHost", &tmp)) {
		result = false;
	}
	else {
		ADDRINFOEX hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		PADDRINFOEX res = nullptr;
		if (GetAddrInfoEx(tmp.c_str(), NULL, NS_DNS, NULL, &hints, &res, NULL, NULL, NULL, NULL) == NO_ERROR) {
			for (ADDRINFOEX* item = res; item != nullptr; item = item->ai_next) {
				if (item->ai_family != AF_INET) {
					continue;
				}
				// Take the first good IP address for the name
				syslogIP = reinterpret_cast<struct sockaddr_in*>(item->ai_addr)->sin_addr.S_un.S_addr;
				break;
			}
			FreeAddrInfoEx(res);
		}
	}
	if (!ReadRegistryString(key, L"SyslogPort", &tmp)) {
		result = false;
	}
	else {
		long portNum = wcstoul(tmp.c_str(), NULL, 10);
		if (portNum == 0 || portNum > 65535) {
			portNum = PORT_NUMBER_DEFAULT;
			result = false;
		}
		syslogPort = htons(static_cast<u_short>(portNum));
	}
	RegCloseKey(key);
	return result;
}

DWORD __stdcall EvtCallback(EVT_SUBSCRIBE_NOTIFY_ACTION Action, PVOID UserContext, EVT_HANDLE Event) {
	if (Action != EvtSubscribeActionDeliver) {
		return 0;
	}
	
	EVT_HANDLE renderCtx = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
	DWORD bufferSizeRequired = 0;
	DWORD propertyCount = 0;
	if (EvtRender(renderCtx, Event, EvtRenderEventValues, 0, NULL, &bufferSizeRequired, &propertyCount) == TRUE || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return 0;
	}
	std::vector<uint8_t> buffer(bufferSizeRequired);
	if (EvtRender(renderCtx, Event, EvtRenderEventValues, bufferSizeRequired, &buffer[0], &bufferSizeRequired, &propertyCount) != TRUE) {
		return 0;
	}
	if (propertyCount <= EvtSystemUserID) {
		return 0;
	}

	const EVT_VARIANT* properties = reinterpret_cast<EVT_VARIANT*>(&buffer[0]);
	if (properties[EvtSystemProviderName].Type != EvtVarTypeString) {
		return 0;
	}
	const WCHAR* providerName = properties[EvtSystemProviderName].StringVal;
	if (properties[EvtSystemTimeCreated].Type != EvtVarTypeFileTime) {
		return 0;
	}
	SYSTEMTIME sysTime;
	FileTimeToSystemTime(reinterpret_cast<const FILETIME*>(&properties[EvtSystemTimeCreated].FileTimeVal), &sysTime);
	if (properties[EvtSystemProcessID].Type != EvtVarTypeUInt32) {
		return 0;
	}
	uint32_t pid = properties[EvtSystemProcessID].UInt32Val;
	if (properties[EvtSystemComputer].Type != EvtVarTypeString) {
		return 0;
	}
	const WCHAR* computerName = properties[EvtSystemComputer].StringVal;
	if (properties[EvtSystemEventID].Type != EvtVarTypeUInt16) {
		return 0;
	}
	uint16_t eventID = properties[EvtSystemEventID].UInt16Val;
	
	bufferSizeRequired = 0;
	EVT_HANDLE metadata = EvtOpenPublisherMetadata(NULL, providerName, NULL, LOCALE_NEUTRAL, 0);
	if (EvtFormatMessage(metadata, Event, 0, 0, NULL, EvtFormatMessageEvent, 0, NULL, &bufferSizeRequired) == TRUE) {
		return 0;
	}
	DWORD err = GetLastError();
	if ( err != ERROR_INSUFFICIENT_BUFFER ) {
		wprintf(L"Failed to EvtFormatMessage: %d\n", err);
		EvtClose(metadata);
		EvtClose(renderCtx);
		return 0;
	}
	std::vector<WCHAR> formatBuffer(bufferSizeRequired);
	if (EvtFormatMessage(metadata, Event, 0, 0, NULL, EvtFormatMessageEvent, (DWORD)formatBuffer.size(), &formatBuffer[0], &bufferSizeRequired) == TRUE) {
		char msg[2048];

		SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (s < 0) {
			return 0;
		}
		snprintf(msg, sizeof(msg),
				"<%d>1 %04u-%02u-%02uT%02u:%02u:%02u.%03uZ %S %S %d %d - %S", 
				3, // system daemon
				sysTime.wYear, 
				sysTime.wMonth, 
				sysTime.wDay, 
				sysTime.wHour, 
				sysTime.wMinute, 
				sysTime.wSecond,
				sysTime.wMilliseconds,
				computerName,
				providerName,
				(int)eventID,
				(int)pid,			
				&formatBuffer[0]);
		struct sockaddr_in sin;
		sin.sin_family = AF_INET;
		sin.sin_addr.S_un.S_addr = syslogIP;
		sin.sin_port = syslogPort;

		sendto(s, msg, (int)strlen(msg), 0, reinterpret_cast<const sockaddr*>(&sin), sizeof(sin));
		closesocket(s);

	}
	EvtClose(metadata);
	EvtClose(renderCtx);
	
	return 0;
}

int RealMain(HANDLE stopEvent) {
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	(void)LoadSettingsFromRegistry();
	if (syslogIP == INADDR_NONE) {
		wprintf(L"FATAL: you did not set SyslogHost in HKLM\\%s\n", regKeyName.c_str());
		return -1;
	}

	EVT_HANDLE channels = EvtOpenChannelEnum(NULL, 0);
	if (channels == NULL) {
		wprintf(L"Failed to enum channels: %d\n", GetLastError());
		return 1;
	}

	bool failedSome = false;
	std::vector<EVT_HANDLE> subscriptions;
	while (1) {
		DWORD nameLen = 0;
		if (EvtNextChannelPath(channels, 0, NULL, &nameLen) == TRUE || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			break;
		}
		std::vector<WCHAR> name(nameLen);
		if (EvtNextChannelPath(channels, (DWORD)name.size(), &name[0], &nameLen) != TRUE) {
			break;
		}
		EVT_HANDLE hnd = EvtSubscribe(NULL, NULL, &name[0], L"*", NULL, NULL, &EvtCallback, EvtSubscribeToFutureEvents);
		if (hnd == NULL) {
			DWORD err = GetLastError();
			if (err == ERROR_NOT_SUPPORTED ) {
				continue; // just skip
			}
			wprintf(L"Failed to subscribe to %s: %d\n", &name[0], err);
			failedSome = true;
			continue;
		}
		subscriptions.push_back(hnd);
	}

	EvtClose(channels);
	while (1) {
		if (stopEvent != NULL) {
			WaitForSingleObject(stopEvent, INFINITE);
			break;
		}
		else {
			Sleep(1000);
		}
	}
	for (auto hnd : subscriptions) {
		EvtClose(hnd);
	}

	WSACleanup();
	return 0;
}

WCHAR SVCNAME[] = L"EvtSyslog";

SERVICE_STATUS          gSvcStatus;
SERVICE_STATUS_HANDLE   gSvcStatusHandle;
HANDLE                  ghSvcStopEvent = NULL;

VOID WINAPI SvcCtrlHandler(DWORD dwCtrl);
VOID ReportSvcStatus(DWORD dwCurrentState,
	DWORD dwWin32ExitCode,
	DWORD dwWaitHint); 
VOID SvcInit(DWORD dwArgc, LPTSTR* lpszArgv);

bool Install_CopyFile(std::wstring* newLocation) {
	PWSTR programFiles;
	if (SHGetKnownFolderPath(FOLDERID_UserProgramFiles, 0, NULL, &programFiles) != S_OK) {
		return false;
	}
	std::wstring fullPath = programFiles;
	CoTaskMemFree(programFiles);
	fullPath += L"\\";
	WCHAR myPathBuf[MAX_PATH];
	if (GetModuleFileName(NULL, myPathBuf, _countof(myPathBuf)) == 0) {
		return false;
	}
	std::wstring myPath = myPathBuf;
	size_t slashPos = myPath.find_last_of('\\');
	if (slashPos == myPath.npos) {
		return false;
	}
	fullPath += myPath.substr(slashPos + 1);

	if (!CopyFile(myPath.c_str(), fullPath.c_str(), TRUE)) {
		return false;
	}
	*newLocation = fullPath;
	return true;
}
//
// Purpose: 
//   Installs a service in the SCM database
//
// Parameters:
//   None
// 
// Return value:
//   None
//
VOID SvcInstall()
{
	std::wstring newLocation;
	if (!Install_CopyFile(&newLocation)) {
		printf("Failed to copy the file\n");
		return;
	}
	SC_HANDLE schSCManager;
	SC_HANDLE schService;

	// Get a handle to the SCM database. 
	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager) {
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	// Create the service

	schService = CreateService(
		schSCManager,              // SCM database 
		SVCNAME,                   // name of service 
		SVCNAME,                   // service name to display 
		SERVICE_ALL_ACCESS,        // desired access 
		SERVICE_WIN32_OWN_PROCESS, // service type 
		SERVICE_AUTO_START,      // start type 
		SERVICE_ERROR_NORMAL,      // error control type 
		newLocation.c_str(),                    // path to service's binary 
		NULL,                      // no load ordering group 
		NULL,                      // no tag identifier 
		NULL,                      // no dependencies 
		NULL,                      // LocalSystem account 
		NULL);                     // no password 

	if (schService == NULL)	{
		printf("CreateService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}
	else {
		printf("Service installed successfully to %S\n", newLocation.c_str());
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}

//
// Purpose: 
//   Entry point for the service
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
// 
// Return value:
//   None.
//
VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
	// Register the handler function for the service

	gSvcStatusHandle = RegisterServiceCtrlHandler(
		SVCNAME,
		SvcCtrlHandler);

	if (!gSvcStatusHandle)	{
		return;
	}

	// These SERVICE_STATUS members remain as set here

	gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	gSvcStatus.dwServiceSpecificExitCode = 0;

	// Report initial status to the SCM

	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

	// Perform service-specific initialization and work.

	SvcInit(dwArgc, lpszArgv);
}

//
// Purpose: 
//   The service code
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
// 
// Return value:
//   None
//
VOID SvcInit(DWORD dwArgc, LPTSTR* lpszArgv)
{
	// TO_DO: Declare and set any required variables.
	//   Be sure to periodically call ReportSvcStatus() with 
	//   SERVICE_START_PENDING. If initialization fails, call
	//   ReportSvcStatus with SERVICE_STOPPED.

	// Create an event. The control handler function, SvcCtrlHandler,
	// signals this event when it receives the stop control code.

	ghSvcStopEvent = CreateEvent(
		NULL,    // default security attributes
		TRUE,    // manual reset event
		FALSE,   // not signaled
		NULL);   // no name

	if (ghSvcStopEvent == NULL)
	{
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	// Report running status when initialization is complete.

	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

	RealMain(ghSvcStopEvent);
	ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

//
// Purpose: 
//   Sets the current service status and reports it to the SCM.
//
// Parameters:
//   dwCurrentState - The current state (see SERVICE_STATUS)
//   dwWin32ExitCode - The system error code
//   dwWaitHint - Estimated time for pending operation, 
//     in milliseconds
// 
// Return value:
//   None
//
VOID ReportSvcStatus(DWORD dwCurrentState,
	DWORD dwWin32ExitCode,
	DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;

	// Fill in the SERVICE_STATUS structure.

	gSvcStatus.dwCurrentState = dwCurrentState;
	gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
	gSvcStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		gSvcStatus.dwControlsAccepted = 0;
	else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	if ((dwCurrentState == SERVICE_RUNNING) ||
		(dwCurrentState == SERVICE_STOPPED))
		gSvcStatus.dwCheckPoint = 0;
	else gSvcStatus.dwCheckPoint = dwCheckPoint++;

	// Report the status of the service to the SCM.
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

//
// Purpose: 
//   Called by SCM whenever a control code is sent to the service
//   using the ControlService function.
//
// Parameters:
//   dwCtrl - control code
// 
// Return value:
//   None
//
VOID WINAPI SvcCtrlHandler(DWORD dwCtrl)
{
	// Handle the requested control code. 

	switch (dwCtrl)
	{
	case SERVICE_CONTROL_STOP:
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

		// Signal the service to stop.

		SetEvent(ghSvcStopEvent);
		ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);

		return;

	case SERVICE_CONTROL_INTERROGATE:
		break;

	default:
		break;
	}

}

int main(int argc, const char* argv[])
{
	// If command-line parameter is "install", install the service. 
	// Otherwise, the service is probably being started by the SCM.

	if (argc > 1) {
		if (!strcmp(argv[1], "install")) {
			SvcInstall();
			return 0;
		}
		else if (!strcmp(argv[1], "noservice")) {
			RealMain(NULL);
			exit(0);
		}
	}

	SERVICE_TABLE_ENTRY DispatchTable[] =
	{
		{ SVCNAME, (LPSERVICE_MAIN_FUNCTION)SvcMain },
		{ NULL, NULL }
	};

	if (!StartServiceCtrlDispatcher(DispatchTable)){
		return 1;
	}
	return 0;
}