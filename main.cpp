#include <string>
#include <iostream>
#include <vector>
#include <array>
#include <format>
#include "win.h"
#include "rustTypes.h"
#include "mitigations.h"
#include "remoteProcess.h"
#include "sigScanner.h"

using SigScanner::Signature;

#define debugprint(...) printf("deb " __VA_ARGS__)

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

#define PROPAGATED_INPUT "te"

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
			
			HANDLE token = 0;
			if (OpenProcessToken(handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
				TOKEN_PRIVILEGES tokenPrivileges;
				tokenPrivileges.PrivilegeCount = 4;
				if (AdjustTokenPrivileges(token, false, &tokenPrivileges, sizeof(tokenPrivileges), nullptr, 0))
					debugprint("adjusted?\n");
			}

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
#ifndef PROPAGATED_INPUT
			std::getline(std::cin, line);
#else
			line = PROPAGATED_INPUT;
#endif

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
				printf("global state %p\n", (void*) globalState);

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
				// if no getPermissions, permissions are got from field, skipping any function
				newPerms = impersonator[getPermissions](lstate*, impersonator.permissions) -> lstate_impersonator_getPermissions
				impersonator.permissions = newPerms
				if (!(newPerms & ...1))
					RBX::Security::errorThreadPermission(~(byte) newPerms & ...1, char* operation, char* details)

				lstate_impersonator_getPermissions(...):
					tries to find lua function in stack and to get permissions from it proto->userdata
					(if no lua function, some global value (hardcoded?) is used)
					gets permissions from lstate->userdata
					returns all these permissions & with each other and with original permissions (2nd arg)

				another way is to find RBX::Security::ThreadImpersonator()
				and to patch it so it would modify impresonator.getPermissions to custom fn that'll allow everything
				*/

				bool patched = false;
				MODULEENTRY32W mainModule = *(studio.snapshotModules().begin());
				size_t baseAddr = (size_t) mainModule.modBaseAddr;
				size_t baseSize = (size_t) mainModule.modBaseSize;
				
				debugprint("base image %p %llx\n", (void*) baseAddr, baseSize);

				const u64 bufSize = 4096;
				u8 buf[bufSize];

				MemoryReaders::RemoteProcessMemoryReader remoteReader(studio.getHandle(), baseAddr, baseSize);
				size_t codePtr = SigScanner::scanFirst<MemoryReaders::RemoteProcessMemoryReader>(remoteReader, Signature::parse("48 81 CB 00 FF FF FF"), { &buf[0], bufSize});
				if (codePtr == SigScanner::notFound) throw std::runtime_error("couldn't find signature");
				debugprint("found [or rbp, -256] (%p)\n", (void*)codePtr);

				const u8 payload[] = "\xB8\xFF\xFF\xFF\xFF\xC3"; // mov eax, 0x00_00_FF_FF; ret;

				studio.readMemory(codePtr -= 128, &buf);
				size_t offset = SigScanner::buf::scanFirst<SigScanner::direction::backwards>(Signature::parse("CC CC CC CC"), {&buf[0], 128})
					+ 4; // size of signature

				debugprint("found the start of routine %p\n", (void*)(codePtr + offset));

				if (memcmp(&buf[offset], payload, sizeof(payload) - 1) != 0) {
					studio.writeMemory(codePtr + offset, payload, sizeof(payload) - 1);
					printf("patched base+%llx\n", (codePtr + offset - baseAddr));
					patched = true;
				} else {
					printf("already patched base+%llx\n", (codePtr + offset - baseAddr));
				}

				if (!patched)
					throw std::runtime_error("couldn't patch any lstate_impersonator::getPermissions");
			}
			else if (stringStartsWith("scheduler", command)) {
				printf("scheduler querying isn't implemented for now\n");
				/*
				
				old: 😭😭😭😭
				pRVar6 = RBX::Scheduler::GetScheduler(); (e8 ?? ?? ?? ??)
				...
				FUN_1433798e0("TaskSchedulerHang", "waiting for async task workers to stop timed out"); ->
				lea rcx, [rip + ...] = 48 8d 0d ?? ?? ?? ??
				...

				(function is large enough (in old version 995 bytes)

				new:
				GetScheduler is inlined


					
				*/

				RemoteProcess::ModuleSnapshot snapshot = studio.snapshotModules();
				MODULEENTRY32W mainModule = *snapshot.begin();
				size_t baseAddr = (size_t)mainModule.modBaseAddr;
				size_t baseSize = (size_t)mainModule.modBaseSize;

				const u64 bufSize = 4096;
				u8 buf[bufSize];


				bool found = false;
				MemoryReaders::RemoteProcessMemoryReader remoteReader(studio.getHandle(), baseAddr, baseSize);
				// 0x0D - rcx; 0x15 - rdx
				SigScanner::scan<MemoryReaders::RemoteProcessMemoryReader>(remoteReader, Signature::parse("48 8D 15 ? ? ? ?"), {&buf[0], bufSize},
					[&](SigScanner::SigScannerStatus& status1, size_t matchedAddr, u8* matched) {
						i32 ripOffset = *(i32*)((size_t) matched + 3);
						size_t leaRefersTo = matchedAddr + 7 + ripOffset;

						char strBuf[64];
						strBuf[63] = 0;
						if (!studio.readMemory(leaRefersTo, &strBuf, 63)) return;
						if (strBuf[0] != 'S' || strcmp(&(strBuf[0]), "Script timeout: shutdown deadline reached") != 0) return;
							
						debugprint("lea %llX refers (%llX)\n", matchedAddr, leaRefersTo);

						const size_t codeBufSize = 4096;
						u8* codeBuf = new u8[codeBufSize];
						studio.readMemory(matchedAddr - codeBufSize, codeBuf, codeBufSize);
						size_t startOffset = codeBufSize - 2;
						while (*(u16*)(&(codeBuf[startOffset])) != 0xCCCC && startOffset > 2) startOffset--;
						while (codeBuf[startOffset] == 0xCC && startOffset < codeBufSize) startOffset++;

						size_t startOfRoutine = matchedAddr - codeBufSize + startOffset;
						debugprint("start of the routine: %llX\n", startOfRoutine);

						studio.readMemory(startOfRoutine, codeBuf, codeBufSize);
						MemoryReaders::NoopReader noop{ codeBufSize };
						SigScanner::buf::scan<SigScanner::direction::backwards>(Signature::parse("E8 ? ? ? ?"), { codeBuf, codeBufSize },
							[&](SigScanner::SigScannerStatus& status2, size_t matchedAddr, u8* matched) {
								i32 offset = *(i32*)(matched + 1);
								const size_t maxFnSize = 128 * 3;
								u8 schedulerElapsedTimeFn[maxFnSize];

								size_t schedulerElapsedTimePtr = startOfRoutine + matchedAddr + 5 + offset;
								if (!studio.readMemory(schedulerElapsedTimePtr, &schedulerElapsedTimeFn)) return;

								size_t fnSize = SigScanner::buf::scanFirst(Signature::parse("CC CC CC CC"), { &schedulerElapsedTimeFn[0], maxFnSize});
								// while (*(u32*)&schedulerElapsedTimeFn[fnSize] != 0xCCCCCCCC && fnSize < (maxFnSize - 4)) fnSize += 1;
								if (fnSize < 0x40 || fnSize == SigScanner::notFound) return; // too small fn (normal is 0xF1 (241))
								// mov rax, gs:[58] (TLS)
								if (!SigScanner::buf::scanHas(Signature::parse("65 48 8B 04 25 58 00 00 00"), { &schedulerElapsedTimeFn[0], fnSize })) return;

								debugprint("taskScheduler.elapsedTime fn %llX (?)\n", schedulerElapsedTimePtr);

								// mov ecx, i32; call [rip + i32]
								// just before allocator, and constructor afterwards
								SigScanner::buf::scan(Signature::parse("B9 ? ? ? ? E8"), { &schedulerElapsedTimeFn[0], fnSize },
									[&](SigScanner::SigScannerStatus& status3, size_t offsetFromStart, u8* matched) {
										offsetFromStart += 5;

										i32 ecxValue = *(i32*)(matched + 1); // ecx is 1st arg to _cxxNew
										if (ecxValue > 100000 || ecxValue < 100) return;

										debugprint("scheduler size (maybe) - %d\n", ecxValue);
										
										// test rax, rax; jz [rip + i8]; call [rip + i32];
										const Signature schedulerNewSignature = Signature::parse("48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ??");
										size_t contructingIndex = SigScanner::buf::scanFirst(schedulerNewSignature, { &schedulerElapsedTimeFn[offsetFromStart], fnSize - offsetFromStart - 1 });
										if (contructingIndex == SigScanner::notFound) return;

										offsetFromStart += contructingIndex + schedulerNewSignature.length();
										size_t schedulerConstructor = *(i32*)(&schedulerElapsedTimeFn[offsetFromStart - 4])
											+ schedulerElapsedTimePtr + offsetFromStart;

										debugprint("found scheduler constructor (%p)\n", schedulerConstructor);
										
										// mov 64:[rip + i32], rax
										size_t assignSchedulerIndex = SigScanner::buf::scanFirst(Signature::parse("48 89 05 ? ? ? ?"), { &schedulerElapsedTimeFn[offsetFromStart], fnSize - offsetFromStart - 1 });
										if (assignSchedulerIndex == SigScanner::notFound) return;

										offsetFromStart += assignSchedulerIndex + 7; // signature size
										i32 movRipOffset = *(i32*)(&schedulerElapsedTimeFn[offsetFromStart - 4]);
										size_t schedulerPtrPtr = movRipOffset + schedulerElapsedTimePtr + offsetFromStart;

										size_t schedulerPtr;
										if (studio.readMemory(schedulerPtrPtr, &schedulerPtr)) {
											size_t junk;
											if (schedulerPtr == 0 || studio.readMemory(schedulerPtr, &junk)) { // both pointers are valid (or scheduler isnt initialized)
												found = true;
												printf("scheduler (%p):\n", schedulerPtr);
												printf("\tscheduler**: %p (base+%llx)\n", schedulerPtrPtr, schedulerPtrPtr - baseAddr);
												printf("\tscheduler size: %d\n", ecxValue);
												printf("\tscheduler constructor(?): %p (base+%llx)\n", schedulerConstructor, schedulerConstructor - baseAddr);

												// 😭
												status1.cancel();
												status2.cancel();
												status3.cancel();
												return;
											}
										}


										printf("(more likely to be incorrect) scheduler (%p) ", schedulerPtr);
										printf(" **%p (b+%llx) ", schedulerPtrPtr, schedulerPtrPtr - baseAddr);
										printf(" size %d ", ecxValue);
										printf(" constructor %p (b+%llx)\n", schedulerConstructor, schedulerConstructor - baseAddr);
										
;									}
								);

								}
							);

							delete[] codeBuf;
						}
				);

				if (!found)
					throw std::runtime_error("couldn't find scheduler");
			}
			else if (stringStartsWith("test", command)) {
				RemoteProcess::ModuleSnapshot snapshot = studio.snapshotModules();
				MODULEENTRY32W mainModule = *snapshot.begin();
				size_t baseAddr = (size_t)mainModule.modBaseAddr;
				size_t baseSize = (size_t)mainModule.modBaseSize;

				const u64 bufSize = 4096;
				u8 buf[bufSize];


				std::vector<size_t> strs;

				bool found = false;
				MemoryReaders::RemoteProcessMemoryReader remoteReader(studio.getHandle(), baseAddr, baseSize);
				SigScanner::scan<MemoryReaders::RemoteProcessMemoryReader>(remoteReader, Signature::from("name conflict for module '%s'"), {&buf[0], bufSize},
				[&](SigScanner::SigScannerStatus& status1, size_t matchedAddr, u8* matched) {
						strs.push_back(matchedAddr);
				});

				MemoryReaders::RemoteProcessMemoryReader remoteReader1(studio.getHandle(), baseAddr, baseSize);

				std::vector<size_t> calls;

				SigScanner::scan<MemoryReaders::RemoteProcessMemoryReader>(remoteReader1, Signature::parse("48 8D 15 ? ? ? ?"), { &buf[0], bufSize },
				[&](SigScanner::SigScannerStatus& status, size_t matchedAddr, u8* matched) {
					i32 ripOffset = *(i32*)((size_t)matched + 3);
					size_t leaRefersTo = matchedAddr + 7 + ripOffset;

					if (leaRefersTo == strs[0]) {
						const usize codeSize = 512;
						u8 code[codeSize];
						studio.readMemory(matchedAddr - codeSize, &code);
						usize routineStart = SigScanner::buf::scanFirst<SigScanner::direction::backwards>(Signature::parse("CC CC CC CC"), { &code[0], codeSize });
						routineStart += 4;
						calls.push_back(matchedAddr - codeSize + routineStart);
						debugprint("%p!!\n", matchedAddr - codeSize + routineStart);
					}
				});

				MemoryReaders::RemoteProcessMemoryReader remoteReader2(studio.getHandle(), baseAddr, baseSize);
				SigScanner::scan<MemoryReaders::RemoteProcessMemoryReader>(remoteReader2, Signature::parse("E8 ? ? ? ?"), { &buf[0], bufSize },
					[&](SigScanner::SigScannerStatus& status, size_t matchedAddr, u8* matched) {
						i32 ripOffset = *(i32*)((size_t)matched + 1);
						size_t callRefersTo = matchedAddr + 5 + ripOffset;

						if (callRefersTo == calls[0]) {
							const usize codeSize = 64;
							u8 code[codeSize];
							studio.readMemory(matchedAddr - codeSize, &code);
							// lea rdx, [rel32]
							usize i = SigScanner::buf::scanFirst<SigScanner::direction::backwards>(Signature::parse("4C 8D 05 ? ? ? ?"), { &code[0], codeSize });
							if (i == SigScanner::notFound) return;
							i32 ripOffset = *(i32*)((size_t)&code[i] + 3);
							size_t leaRefersTo = matchedAddr - codeSize + i + 7 + ripOffset;
							debugprint("lea %p -> %p\n", matchedAddr - codeSize + i, leaRefersTo);

							struct libfnEntry {
								usize name;
								usize fn;
							};

							usize entryPtr = leaRefersTo;
							libfnEntry entry;
							
							std::string allFns = "fns:";

							while (true) {
								if (!studio.readMemory(entryPtr, &entry)) return;

								if (entry.name == 0) break;

								const usize maxStrSize = 128;
								char str[maxStrSize];
								if (!studio.readMemory(entry.name, &str)) return;
								str[maxStrSize - 1] = '\x00';

								allFns += std::format("\n\t{} {:x}", &str[0], entry.fn);
								entryPtr += sizeof(entry);
							}
							



							

							

							


							printf("call [lua_reglib] %p!! %s\n", matchedAddr, allFns.c_str());
						}
					});
			}
		} catch (const std::exception& e) {
			std::cerr << "error: " << e.what() << '\n';
		}

#ifdef PROPAGATED_INPUT
		return 0;
#endif
	}

	return 0;
}