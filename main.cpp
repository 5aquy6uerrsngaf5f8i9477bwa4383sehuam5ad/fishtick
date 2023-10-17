#include <string>
#include <iostream>
#include <vector>
#include <array>
#include "win.h"
#include "rustTypes.h"
#include "utf16-mitigation.h"

u32 findPIDfromProcessName(std::string processNameMultiByteString) {
	std::wstring processName = widen(processNameMultiByteString);

	const wchar_t* wideProcessName = processName.c_str();
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	u32 processId = 0;
	if (Process32FirstW(snapshot, &entry)) {
		while (Process32NextW(snapshot, &entry)) {
			if (wcscmp(entry.szExeFile, wideProcessName) == 0) {
				processId = entry.th32ProcessID;
				goto foundProcessId;
			}
		}
	}

foundProcessId:
	CloseHandle(snapshot);
	return processId;
}

HANDLE tryToOpen(u32 pid) {
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid);
	if (processHandle == INVALID_HANDLE_VALUE) throw std::runtime_error("could not open process");

	u32 exitCode;
	if (!GetExitCodeProcess(processHandle, &exitCode)) throw std::runtime_error("could not query process exit code");
	if (exitCode != STILL_ACTIVE) throw std::runtime_error("process is terminated");

	return processHandle;
}

class RemoteProcess {
public:
	RemoteProcess(HANDLE handle) : processHandle(handle) {
	
	}

	template <typename T>
	bool readMemory(size_t address, T* out, size_t size) {
		return ReadProcessMemory(processHandle, (void*) address, out, size, nullptr);
	}

	template <typename T>
	inline bool readMemory(size_t address, T* out) {
		return readMemory(address, out, sizeof(T));
	}

	template <typename T>
	bool writeMemory(size_t address, T* in, size_t size) {
		return WriteProcessMemory(processHandle, (void*)address, in, size, nullptr);
	}

	template <typename T>
	inline bool writeMemory(size_t address, T* in) {
		return writeMemory(address, in, sizeof(T));
	}

	~RemoteProcess() {
		CloseHandle(processHandle);
	}
protected:
	HANDLE processHandle;

};

bool stringStartsWith(std::string str, std::string startShouldBe) {
	size_t strSize = str.size();
	size_t startSize = startShouldBe.size();
	
	if (startSize > strSize) return false;
	size_t charsToCheck = std::min(strSize, startSize);
	for (size_t i = 0; i < charsToCheck; i++)
		if (startShouldBe[i] != str[i]) return false;

	return true;
}

inline bool isSpace(char c) {
	return c == ' ' || c == '\t';
}

inline size_t findNextSpace(const std::string& str, size_t offset) {
	size_t strSize = str.size();
	offset--;
	while (++offset < strSize) 
		if (isSpace(str[offset])) return offset;

	return std::string::npos;
}

inline std::vector<std::string> splitBySpaces(const std::string& line) {
	std::vector<std::string> splitted;
	if (line.size() == 0) return splitted;

	size_t last = 0;
	size_t next = 0;
	while (last < line.size() && isSpace(line[last])) last++; // trim start

	while ((next = findNextSpace(line, last)) != std::string::npos) {
		splitted.push_back(line.substr(last, next - last));
		last = next + 1;
		while (last < line.size() && isSpace(line[last])) last++; // ignore spaces in a row
	};

	if (last < line.size() && line[last] != ' ') {
		while (last >= 0 && isSpace(line[last])) last--; // trim end
		splitted.push_back(line.substr(last));
	}
	
	return splitted;
}



int main() {
start:
	u32 pid = findPIDfromProcessName("RobloxStudioBeta.exe");
	if (!pid) {
		std::cerr << "no RobloxStudioBeta.exe is found\n";
	}

	HANDLE handle = INVALID_HANDLE_VALUE;
	try {
		if (pid) {
			handle = tryToOpen(pid);
			printf("opened handle for %d\n", pid);
		}
	} catch (const std::exception& e) {
		std::cerr << e.what() << '\n';
	}
	
	RemoteProcess studio(handle);
cmdLoop:
	while (true) {
		try {
			std::string line;
			std::getline(std::cin, line);

			std::vector<std::string> args = splitBySpaces(line);

			size_t argc = args.size();
			if (argc == 0) continue;

			const std::string& command = args[0];

			if (stringStartsWith("exit", command)) break;
			if (stringStartsWith("reattach", command)) goto start;


			if (stringStartsWith("global", command)) {
				if (argc < 2)
					throw std::runtime_error("expected address as an argument");

				size_t address = std::stoull(args[1], nullptr, 16);

				size_t globalState = 0;
				studio.readMemory(address + 24, &globalState);
				printf("global state %p\n", globalState);

				size_t ptrEncrKey = globalState + 0xC18 // got from math.random
					+ 8;

				u64 newPtrEncrKey[4] = { 1, 0, 0, 0 };
				studio.writeMemory(ptrEncrKey, &newPtrEncrKey);
			}
		} catch (const std::exception& e) {
			std::cerr << "error: " << e.what() << '\n';
		}
	}

	return 0;
}