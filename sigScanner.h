#pragma once
#include <cstring>
#include <utility>
#include <functional>
#include <algorithm>
#include <stdexcept>
#include <vector>
#include "memory"
#include "rustTypes.h"
#include "win.h"

struct Buffer {
	u8* ptr;
	usize len;

	template <typename T>
	inline Buffer(T* ptr, usize len) : ptr((u8*)ptr), len(len) {}
};

namespace MemoryReaders {
	template <typename DerivedReader>
	class BaseMemoryReader {
	public:
		BaseMemoryReader(size_t address, size_t size) : address(address), memSize(size) {}
		BaseMemoryReader(Buffer buf) : address((size_t) buf.ptr), memSize(buf.len) {}

		template <typename T>
		inline size_t read(T* buf, size_t toRead) noexcept {
			size_t read = ((DerivedReader*)this)->rawread((u8*)buf, toRead);
			offset += read;
			return read;
		}

		inline void stepForward(size_t bytes) noexcept {
			offset += bytes;
			if (offset > memSize)
				offset = memSize;
		}

		inline void stepBack(size_t bytes) noexcept {
			if (offset > bytes) {
				offset -= bytes;
			} else {
				offset = 0;
			}
		}

		inline size_t size() const noexcept { return memSize; }
		inline size_t position() const noexcept { return offset; }
		inline size_t left() const noexcept { return memSize - offset; }

		inline size_t startAddress() const noexcept { return address; }
		inline size_t currentAddress() const noexcept { return address + offset; }
		inline bool isEnded() const noexcept { return offset >= memSize; }
		inline bool isAtStart() const noexcept { return offset == 0; }


	protected:
		size_t address;
		size_t offset = 0;
		size_t memSize;
	};

	class MemoryReader : public BaseMemoryReader<MemoryReader> {
	public:
		size_t rawread(u8* buf, size_t toRead) const noexcept {
			size_t willRead = std::min(toRead, left());
			memcpy(buf, (u8*)address + offset, willRead);
			return willRead;
		}
	};

	class RemoteProcessMemoryReader : public BaseMemoryReader<RemoteProcessMemoryReader> {
	public:
		RemoteProcessMemoryReader(HANDLE processHandle, size_t address, size_t size) : BaseMemoryReader(address, size), processHandle(processHandle) {}
		RemoteProcessMemoryReader(HANDLE processHandle, Buffer buf) : BaseMemoryReader(buf), processHandle(processHandle) {}

		size_t rawread(u8* buf, size_t toRead) const noexcept {
			size_t willRead = std::min(toRead, left());
			fReadProcessMemory(processHandle, (void*)currentAddress(), buf, willRead, &willRead);
			return willRead;
		}
	protected:
		HANDLE processHandle;
	};

	class NoopReader : public BaseMemoryReader<NoopReader> {
	public:
		NoopReader(size_t size) : BaseMemoryReader(0, size) {}

		size_t rawread(u8* buf, size_t toRead) const noexcept { return memSize; }
	};
}

namespace SigScanner {
	class Signature {
	private:
		class SigUnderlying {
		public:
			const u8* signature;
			const char* mask;
			
			SigUnderlying(const u8* sig, const char* mask, bool noCopy) {
				if (noCopy) {
					this->signature = sig;
					this->mask = mask;
				} else {
					usize maskLen = strlen(mask);
					char* newMask = new char[maskLen + 1];
					u8* newSig = new u8[maskLen];

					std::strcpy(newMask, mask);
					std::copy(sig, sig + maskLen, newSig);

					this->mask = newMask;
					this->signature = newSig;
				}
			}
		};

		const static inline u8 hexCharToNum(const char c) {
			if (c >= 'A' && c <= 'F') {
				return c - 'A' + 10;
			}

			if (c >= '0' && c <= '9') {
				return c - '0';
			}

			throw std::runtime_error("cant convert char from hex to num");
		}

	protected:
		static const char MASK_NOCHECK = '?';
		static const char MASK_EQCHECK = 'x';

		const u8* signature;
		const char* mask;

		size_t len;
		std::shared_ptr<SigUnderlying> data;
	public:
		template <typename T>
		Signature(const T* sig, const char* mask, bool noCopy = true) {
			this->data = std::make_shared<SigUnderlying>((u8*)sig, mask, noCopy);
			this->signature = data->signature;
			this->mask = data->mask;
			this->len = strlen(mask);
		}

		~Signature() {

		}

	/*	Signature(const Signature&& other) :
			signature(other.signature),
			mask(other.mask),
			data(data),
			len(other.len) {}*/

		const static Signature parse(const char* csig) {
			std::vector<u8> sig;
			std::vector<char> mask;

			const usize siglen = strlen(csig);
			for (usize i = 0; i < siglen; i++) {
				char thisChar = csig[i];
				if (thisChar == ' ') continue;
				char nextChar = csig[i + 1];

				if (thisChar == '?') {
					mask.push_back(MASK_NOCHECK);
					sig.push_back(0);
					if (nextChar == '?') {
						i++;
						continue;
					}
				} else {
					// 2char byte
					if (nextChar != ' ' && nextChar != '\x00' && nextChar != '?') {
						u8 high = hexCharToNum(thisChar);
						u8 low = hexCharToNum(nextChar);

						sig.push_back((high << 4) | low);
						mask.push_back(MASK_EQCHECK);
						i++; // skip low byte part
					} else {
						sig.push_back(hexCharToNum(thisChar));
						mask.push_back(MASK_EQCHECK);
					}
				}
			}

			u8* sigPtr = new u8[sig.size()];
			char* maskPtr = new char[mask.size() + 1];

			std::copy(sig.begin(), sig.end(), sigPtr);
			std::copy(mask.begin(), mask.end(), maskPtr);
			maskPtr[mask.size()] = '\x00';

			return { sigPtr, maskPtr, false };
		}
		inline const static Signature from(const char* sig) {
			return from(sig, strlen(sig));
		}
		inline const static Signature from(const char* sig, usize sigLen) {
			char* maskPtr = new char[sigLen + 1];
			memset(maskPtr, 'x', sigLen);
			maskPtr[sigLen] = '\x00';
			u8* sigPtr = new u8[sigLen];
			std::copy(sig, sig + sigLen, sigPtr);

			return { sigPtr, maskPtr, false };
		}

		inline bool checkByte(const size_t i, const u8 data) const {
			char maski = mask[i];
			if (maski == MASK_NOCHECK) return true;

			u8 sigi = signature[i];
			if (maski == MASK_EQCHECK && sigi == data) return true;

			return false;
		}

		size_t length() const {
			return len;
		}
	};

	enum direction : u8 { forwards = 0, backwards = 1, rawbackwards = 2, };

	class SigScannerStatus {
	public:
		SigScannerStatus() {}

		inline bool isCancelled() const { return cancelled; }
		inline void cancel() { cancelled = true; }
	private:
		bool cancelled = false;
	};

	const static size_t notFound = (size_t) -1;

	template <typename Reader = MemoryReaders::MemoryReader, direction rawdirection = forwards>
	void scan(Reader& reader, const Signature signature, Buffer buf, std::function<void(SigScannerStatus&, size_t, u8*)> controller) noexcept {
		SigScannerStatus status;
		
		size_t sigLength = signature.length();
		if (sigLength == 0) return;

		if (rawdirection == backwards)
			reader.stepForward(reader.size());

		bool inversed = rawdirection >= backwards;
		bool first = rawdirection == rawbackwards;
		while (first || (inversed ? (!reader.isAtStart()) : (!reader.isEnded()))) {
			if (inversed) first = false; // do {} while () emulating
			if (inversed) reader.stepBack(buf.len);

			size_t addressOfRegion = reader.currentAddress();
			size_t read = inversed ? (reader.rawread(buf.ptr, buf.len)) : (reader.read(buf.ptr, buf.len));
			if (read > buf.len) {
				read = buf.len;
				printf("read %llx & buf.len %llx\n", read, buf.len);
			}
			if (inversed)
				if (read != buf.len)
					printf("read != buf.len (sigscan)\n");

			if (read == 0) {
				printf("read 0\n");
			}

			for (size_t i = inversed ? (read - 1 - sigLength) : 0; inversed ? (i > 0) : (i < read); (inversed) ? (--i) : (++i)) {
				if (signature.checkByte(0, buf.ptr[i])) {
					bool matched = true;

					if (sigLength >= 2) {
						u8* innerBuf = buf.ptr + i;
						for (size_t i2 = 1; i2 < sigLength; ++i2) {
							if (!signature.checkByte(i2, innerBuf[i2])) {
								matched = false;
								break;
							}
						}
					}

					if (matched) {
						controller(status, addressOfRegion + i, buf.ptr + i);
						if (status.isCancelled()) return;
					}
				}
			}

			size_t reverseStepOn = 0;
			if (inversed) {
				for (size_t i = sigLength; i > 0; --i) {
					if (signature.checkByte(sigLength - 1, buf.ptr[i])) {
						reverseStepOn = i;
						break;
					}
				}
			} else {
				for (size_t i = read - sigLength; i < read; ++i) {
					if (signature.checkByte(0, buf.ptr[i])) {
						reverseStepOn = read - i;
						break;
					}
				}
			}

			if (inversed ? (!reader.isAtStart()) : (!reader.isEnded()) && reverseStepOn)
				if (inversed)
					reader.stepForward(reverseStepOn);
				else 
					reader.stepBack(reverseStepOn);
		}

		return;
	}

	template <typename Reader = MemoryReaders::MemoryReader, direction rawdirection = forwards>
	size_t scanFirst(Reader& reader, Signature signature, Buffer buf) {
		size_t addr = notFound;

		//std::vector<size_t> addrs;
		scan<Reader, rawdirection>(reader, signature, buf, [&addr](SigScannerStatus& status, size_t matchedAddr, u8* matched) {
			addr = matchedAddr;
			//addrs.push_back(matchedAddr);
			status.cancel();
		});

		return addr;
	}

	template <typename Reader = MemoryReaders::MemoryReader>
	bool scanHas(Reader& reader, Signature signature, Buffer buf) {
		bool ret = false;
		scan<Reader>(reader, signature, buf, [&ret](SigScannerStatus& status, size_t matchedAddr, u8* matched) {
			ret = true;
			status.cancel();
		});

		return ret;
	}

	namespace buf {
		template <direction rawdirection = forwards>
		inline void scan(Signature signature, Buffer buf, std::function<void(SigScannerStatus&, size_t, u8*)> controller) {
			MemoryReaders::NoopReader noop{ buf.len };
			SigScanner::scan<MemoryReaders::NoopReader, rawdirection>(noop, signature, buf, controller);
		}

		template <direction rawdirection = forwards>
		inline size_t scanFirst(Signature signature, Buffer buf) {
			MemoryReaders::NoopReader noop{ buf.len };
			return SigScanner::scanFirst<MemoryReaders::NoopReader, rawdirection>(noop, signature, buf);
		}
		
		inline bool scanHas(Signature signature, Buffer buf) {
			MemoryReaders::NoopReader noop{ buf.len };
			return SigScanner::scanHas(noop, signature, buf);
		}
	};	
};

