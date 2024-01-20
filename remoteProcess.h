#pragma once
#include <exception>
#include "rustTypes.h"
#include "mitigations.h"
#include "win.h"

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
	class Memory {

	};
public:
	RemoteProcess(HANDLE handle) : processHandle(handle) {

	}

	template <typename T>
	bool readMemory(size_t address, T* out, size_t size) {
		usize a;
		fReadProcessMemory(processHandle, (void*)address, out, size, &a);
		return a == size;
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
		if (!pid)
			pid = GetProcessId(processHandle);

		return pid;
	}

	HANDLE getHandle() const { return processHandle; }

	~RemoteProcess() {
		CloseHandle(processHandle);
	}
protected:
	HANDLE processHandle;
	u32 pid = 0;
};