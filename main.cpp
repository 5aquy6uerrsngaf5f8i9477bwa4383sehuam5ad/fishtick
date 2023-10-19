#include <string>
#include <iostream>
#include <vector>
#include <array>
#include "win.h"
#include "rustTypes.h"
#include "utf16-mitigation.h"

#define debugprint(...) //printf(__VA_ARGS__)

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
	class ModuleSnapshot {
	public:
		class ModuleIterator {
		private:
			ModuleIterator(ModuleSnapshot& snapshot, bool ended) : snapshot(snapshot), ended(ended) {
				if (!ended) {
					if (!Module32FirstW(snapshot.modulesSnapshot, &snapshot.me32))
						ended = true;
				}
			}

			friend ModuleSnapshot;
		public:
			ModuleIterator operator++() {
				if (!ended) {
					if (!Module32NextW(snapshot.modulesSnapshot, &snapshot.me32))
						ended = true;
				}

				return *this;
			}

			const MODULEENTRY32W& operator*() const { return snapshot.me32; }

			inline friend bool operator== (const ModuleIterator& a, const ModuleIterator& b) { return a.ended == b.ended; }; // no checks by snapshot
			inline friend bool operator!= (const ModuleIterator& a, const ModuleIterator& b) { return a.ended != b.ended; };
		private:
			ModuleSnapshot& snapshot;
			bool ended;
		};
	public:
		ModuleSnapshot(u32 pid) {
			modulesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
			me32.dwSize = sizeof(me32);
		}
		~ModuleSnapshot() {
			if (modulesSnapshot != INVALID_HANDLE_VALUE) {
				CloseHandle(modulesSnapshot);
			}
		}

		ModuleIterator begin() {
			if (iteratorGiven) throw std::runtime_error("module iterators already has been made");
			iteratorGiven = true;

			return { *this, false };
		}

		ModuleIterator end() {
			return { *this, true };
		}
	private:
		HANDLE modulesSnapshot;
		MODULEENTRY32W me32;
		bool iteratorGiven = false;
	};
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

	ModuleSnapshot snapshotModules() {
		return { getPID() };
	}

	u32 getPID() {
		if (!pid) {
			pid = GetProcessId(processHandle);
		}

		return pid;
	}

	~RemoteProcess() {
		CloseHandle(processHandle);
	}
protected:
	HANDLE processHandle;
	u32 pid = 0;
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

std::vector<std::string> splitBySpaces(const std::string& line) {
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

	if (last < line.size()) {
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
			else if (stringStartsWith("reattach", command)) goto start;


			else if (stringStartsWith("global", command)) {
				if (argc < 2)
					throw std::runtime_error("expected lua_state address as an argument");

				size_t lstateAddress = std::stoull(args[1], nullptr, 16);

				size_t globalState = 0;
				studio.readMemory(lstateAddress + 24, &globalState);
				printf("global state %p\n", globalState);

				size_t ptrEncrKey = globalState + 0xC18 // got from math.random
					+ 8;

				u64 newPtrEncrKey[4] = { 1, 0, 0, 0 };
				studio.writeMemory(ptrEncrKey, &newPtrEncrKey);
			}
			else if (stringStartsWith("identityfuck", command)) {
				/*
				
				outdated:
				lea r8, [rip + ...] is 4c 8d 05 ...

				impersonator = RBX::Security::ThreadImpersonator()
				if (!RBX::Security::IsInRole(impersonator, Plugin (1))) {
				  error(piVar8, 1, "create a NetworkClient");

				r8 is 3rd argument (MS __fastcall) so by an error message, RBX::Security::IsInRole can be tracked

				new:

				impersonator = RBX::Security::ThreadImpersonator()
				newPerms = impersonator[getPermissions](lstate*, impersonator.permissions) -> lstate_impersonator_getPermissions
				impersonator.permissions = newPerms
				if (!(newPerms & ...1))
					RBX::Security::errorThreadPermission(~(byte) newPerms & ...1, char* operation, char* details)

				lstate_impersonator_getPermissions(...):
					tries to find lua function in stack and to get permissions from it proto->userdata
					(if no lua function, some global value (hardcoded?) is used)
					gets permissions from lstate->userdata
					returns all these permissions & with each other and with original permissions (2nd arg)
				*/

				RemoteProcess::ModuleSnapshot snapshot = studio.snapshotModules();
				MODULEENTRY32W mainModule = *snapshot.begin();
				size_t baseAddr = (size_t) mainModule.modBaseAddr;
				size_t baseSize = (size_t) mainModule.modBaseSize;
				
				debugprint("base image %p %x\n", (void*) baseAddr, baseSize);


				// TODO: move to a class? like MemoryReader? (rewrite the shit)

				const u64 bufSize = 4096;
				u8 buf[bufSize];
				bool patched = false;

				size_t offset = 0;				
				while (offset < (baseSize - 1)) {
					studio.readMemory(baseAddr + offset, &buf, std::min(baseSize - offset, (u64)bufSize));

					for (size_t i = 0; i < bufSize - 7; i++) {
						if (memcmp(&buf[i], "\x48\x81\xCB\x00\xFF\xFF\xFF", 7) == 0) {
							u8 codeBuf[256];
							size_t codePtr = baseAddr + offset + i;
							debugprint("found [or rbp, -256] (%p)\n", (void*) codePtr);
							studio.readMemory(codePtr -= (sizeof(codeBuf) / 2), &codeBuf);

							size_t codeBufOffset = (sizeof(codeBuf) / 2);
							while (codeBufOffset > 0) {
								if (memcmp(&codeBuf[codeBufOffset], "\xCC\xCC\xCC\xCC", 4) == 0) {
									while (codeBuf[codeBufOffset] == (u8) '\xCC' && codeBufOffset < sizeof(codeBuf))
										codeBufOffset++;
									
									debugprint("found the start of routine %p\n", (void*) (codePtr + codeBufOffset));

									const u8 payload[] = "\xB8\xFF\xFF\x00\x00\xC3";
									if (memcmp(&codeBuf[codeBufOffset], payload, sizeof(payload) - 1) != 0) {
										studio.writeMemory(codePtr + codeBufOffset, payload, sizeof(payload) - 1);
										printf("patched base+%x\n", (void*) (codePtr + codeBufOffset - baseAddr));
										patched = true;
									} else {
										printf("already patched base+%x\n", (void*) (codePtr + codeBufOffset - baseAddr));
									}

									break;
								}

								if (4 > codeBufOffset)
									codeBufOffset = 0;
								else
									codeBufOffset -= 4;
							}
						}

						//if (buf[i] == 0x4C && buf[i + 1] == 0x8D && buf[i + 2] == 0x05) {
						//	i32 ripOffset = *(i32*) (&buf[i + 3]);
						//	size_t leaReferringTo = baseAddr + offset + i + 7 + ripOffset; // 7 = size of lea
						//	debugprint("lea r8, [rip + %x] (%p) (%p)\n", ripOffset, leaReferringTo, baseAddr + offset + i);
					}

					offset += bufSize - 7; // to keep 7 bytes for full lea (or rbp, -256) instruction
				}

				if (!patched)
					throw std::runtime_error("couldn't patch any lstate_impersonator::getPermissions");
			}
		} catch (const std::exception& e) {
			std::cerr << "error: " << e.what() << '\n';
		}
	}

	return 0;
}