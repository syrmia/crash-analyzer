//===- MemoryWrapper.cpp Track down changed memory locations
//--------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/MemoryWrapper.h"
#include <sstream>

using namespace llvm;

#define DEBUG_TYPE "mem-wrapper"

crash_analyzer::MemoryWrapper::MemoryWrapper() {}

void crash_analyzer::MemoryWrapper::dumpOneMemoryLocation(
    std::string Label, uint64_t Addr, uint32_t ByteSize,
    Optional<uint64_t> OptVal) {
  LLVM_DEBUG(std::stringstream SS; std::string StrAddr; std::string StrVal;
             SS << std::hex << Addr; SS >> StrAddr;
             // Size of 64 bits, 16 hex nums
             if (StrAddr.size() < 2 * 8) StrAddr =
                 std::string(2 * 8 - StrAddr.size(), '0') + StrAddr;
             llvm::dbgs() << Label << ": 0x" << StrAddr;
             if (OptVal) {
               SS.clear();
               SS << std::hex << *OptVal;
               SS >> StrVal;
               if (StrVal.size() < 2 * ByteSize)
                 StrVal =
                     std::string(2 * ByteSize - StrVal.size(), '0') + StrVal;
               llvm::dbgs() << " : 0x" << StrVal;
             }

             llvm::dbgs()
             << ", byte size: " << ByteSize << "\n";);
}

Optional<uint64_t> crash_analyzer::MemoryWrapper::ReadUnsignedFromMemory(
    uint64_t addr, uint32_t byte_size, lldb::SBError &error) {

  assert(byte_size <= 8 && "Can't read more than 8 bytes for now!");
  std::string StrVal;
  std::stringstream SS;
  uint64_t alignmentOffset = addr % NUM_OF_BYTES_PER_ADDRESS;
  uint64_t alignedAddr = addr - alignmentOffset;
  uint64_t Val = 0;
  // Only in one aligned location
  if (alignmentOffset + byte_size <= NUM_OF_BYTES_PER_ADDRESS &&
      this->ChangedMemoryAddresses.count(alignedAddr)) {
    uint8_t locationValidity = this->ChangedMemoryAddresses[alignedAddr].first;
    uint8_t validityMask = ((1U << byte_size) - 1) << alignmentOffset;

    uint8_t valid = (locationValidity & validityMask) ^ validityMask;
    // if valid is zero it means that it really is valid
    if (valid != 0) {
      StrVal = "";

      dumpOneMemoryLocation("Addressing invalid location", addr, byte_size,
                            None);
      return None;
    } else {
      Val = ((this->ChangedMemoryAddresses[alignedAddr].second &
              (-1UL >>
               (NUM_OF_BYTES_PER_ADDRESS - byte_size - alignmentOffset) * 8)) >>
             (alignmentOffset * 8));
    }
  }
  // More than one aligned locations are addressed by access
  else if (alignmentOffset + byte_size > NUM_OF_BYTES_PER_ADDRESS &&
           (this->ChangedMemoryAddresses.count(alignedAddr) ||
            this->ChangedMemoryAddresses.count(alignedAddr +
                                               NUM_OF_BYTES_PER_ADDRESS))) {
    uint8_t locationValidity1 = 0xFF;
    uint8_t locationValidity2 = 0xFF;

    if (this->ChangedMemoryAddresses.count(alignedAddr)) {
      locationValidity1 = this->ChangedMemoryAddresses[alignedAddr].first;
    }
    if (this->ChangedMemoryAddresses.count(alignedAddr +
                                           NUM_OF_BYTES_PER_ADDRESS)) {
      locationValidity2 =
          this->ChangedMemoryAddresses[alignedAddr + NUM_OF_BYTES_PER_ADDRESS]
              .first;
    }
    uint8_t validityMask1 =
        ((1U << (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset)) - 1)
        << alignmentOffset;
    uint8_t validityMask2 =
        ((1U << (byte_size - (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset))) -
         1);

    uint8_t valid1 = (locationValidity1 & validityMask1) ^ validityMask1;
    uint8_t valid2 = (locationValidity2 & validityMask2) ^ validityMask2;

    if (valid1 != 0 || valid2 != 0) {
      StrVal = "";
      dumpOneMemoryLocation("Addressing invalid location", addr, byte_size,
                            None);
      return None;
    } else {
      uint64_t Val1 = 0;
      if (this->ChangedMemoryAddresses.count(alignedAddr)) {
        Val1 = this->ChangedMemoryAddresses[alignedAddr].second;
      } else {
        Val1 = this->Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(
            alignedAddr, NUM_OF_BYTES_PER_ADDRESS, error);
      }

      uint64_t Val2 = 0;
      if (this->ChangedMemoryAddresses.count(alignedAddr +
                                             NUM_OF_BYTES_PER_ADDRESS)) {
        Val2 =
            this->ChangedMemoryAddresses[alignedAddr + NUM_OF_BYTES_PER_ADDRESS]
                .second;
      } else {
        Val2 = this->Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(
            alignedAddr + NUM_OF_BYTES_PER_ADDRESS, NUM_OF_BYTES_PER_ADDRESS,
            error);
      }

      Val = (Val1 >> (8 * alignmentOffset)) |
            (((Val2 & (-1UL >> (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset +
                                NUM_OF_BYTES_PER_ADDRESS - byte_size) *
                                   8))
              << (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset) * 8));
    }
  }
  // Read entirely from corefile, we haven't got this address in MemWrapper
  else if (this->Dec != nullptr) {
    Val = this->Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(
        addr, byte_size, error);
  } else {
    return None;
  }
  SS.clear();
  SS << std::hex << Val;
  SS >> StrVal;
  if (StrVal.size() < 2 * byte_size) {
    StrVal = std::string(2 * byte_size - StrVal.size(), '0') + StrVal;
  }

  dumpOneMemoryLocation("Addressing valid location", addr, byte_size, Val);
  return Val;
}

void crash_analyzer::MemoryWrapper::setDecompiler(
    crash_analyzer::Decompiler *Dec) {
  this->Dec = Dec;
}

void crash_analyzer::MemoryWrapper::WriteMemory(uint64_t addr, const void *buf,
                                                size_t size,
                                                lldb::SBError &error) {
  uint64_t alignmentOffset = addr % NUM_OF_BYTES_PER_ADDRESS;
  uint64_t alignedAddr = addr - alignmentOffset;
  std::stringstream SS;
  // iterate 8 bytes per time
  for (uint32_t i = 0; i < size; i += NUM_OF_BYTES_PER_ADDRESS) {
    uint8_t mask = 0xFF;
    if (this->ChangedMemoryAddresses.count(alignedAddr)) {
      mask = (0xFFU << alignmentOffset);
      if (i + NUM_OF_BYTES_PER_ADDRESS - alignmentOffset > size) {
        mask &=
            0xFFU >> (i + NUM_OF_BYTES_PER_ADDRESS - alignmentOffset - size);
      }
      this->ChangedMemoryAddresses[alignedAddr].first |= mask;
    } else {
      lldb::SBError err;
      uint64_t Val = 0;
      if (this->Dec) {
        Val = this->Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(
            alignedAddr, NUM_OF_BYTES_PER_ADDRESS, err);
      }
      this->ChangedMemoryAddresses[alignedAddr] = {0xFF, Val};
    }

    alignedAddr += NUM_OF_BYTES_PER_ADDRESS;
    i -= alignmentOffset;
    alignmentOffset = 0;
  }

  alignmentOffset = addr % NUM_OF_BYTES_PER_ADDRESS;
  alignedAddr = addr - alignmentOffset;
  // iterate 8 bytes per time
  for (uint32_t i = 0; i < size; i += NUM_OF_BYTES_PER_ADDRESS) {
    uint64_t Val = 0;
    // counter = how many bits in byte should we read
    uint32_t counter = size - i > NUM_OF_BYTES_PER_ADDRESS - alignmentOffset
                           ? NUM_OF_BYTES_PER_ADDRESS - alignmentOffset
                           : size - i;
    for (uint32_t j = 0; j < counter; j++)
      Val |= ((uint64_t)((const uint8_t *)buf)[i + j]) << (j * 8);

    lldb::SBError err;
    uint32_t shiftRight =
        (NUM_OF_BYTES_PER_ADDRESS - size + i - alignmentOffset) * 8 >= 0
            ? (NUM_OF_BYTES_PER_ADDRESS - size + i - alignmentOffset) * 8
            : 0;
    this->ChangedMemoryAddresses[alignedAddr].second &=
        ~(((-1UL << 8 * alignmentOffset)) >> shiftRight);
    this->ChangedMemoryAddresses[alignedAddr].second |=
        (Val << 8 * alignmentOffset);

    uint32_t sizeToWrite = size - i > NUM_OF_BYTES_PER_ADDRESS - alignmentOffset
                               ? NUM_OF_BYTES_PER_ADDRESS - alignmentOffset
                               : size - i;
    dumpOneMemoryLocation("Writing location", alignedAddr + alignmentOffset,
                          sizeToWrite, Val);

    alignedAddr += NUM_OF_BYTES_PER_ADDRESS;
    i -= alignmentOffset;
    alignmentOffset = 0;
  }

  this->dump();
}

void crash_analyzer::MemoryWrapper::InvalidateAddress(uint64_t addr,
                                                      size_t size) {
  uint64_t alignmentOffset = addr % NUM_OF_BYTES_PER_ADDRESS;
  uint64_t alignedAddr = addr - alignmentOffset;
  std::stringstream SS;
  // iterate 8 bytes per time
  for (uint32_t i = 0; i < size; i += NUM_OF_BYTES_PER_ADDRESS) {
    uint8_t mask = (0xFFU >> (NUM_OF_BYTES_PER_ADDRESS - alignmentOffset));
    if (i + NUM_OF_BYTES_PER_ADDRESS - alignmentOffset > size) {
      mask |= 0xFFU << (alignmentOffset + size - i);
    }
    if (this->ChangedMemoryAddresses.count(alignedAddr) == 0) {
      lldb::SBError err;
      uint64_t Val = 0;
      if (this->Dec) {
        Val = this->Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(
            alignedAddr, NUM_OF_BYTES_PER_ADDRESS, err);
      }
      this->ChangedMemoryAddresses[alignedAddr] = {0xFF, Val};
    }
    this->ChangedMemoryAddresses[alignedAddr].first &= mask;
    uint32_t sizeToInvalidate =
        size - i > NUM_OF_BYTES_PER_ADDRESS - alignmentOffset
            ? NUM_OF_BYTES_PER_ADDRESS - alignmentOffset
            : size - i;
    dumpOneMemoryLocation("Invalidating location",
                          alignedAddr + alignmentOffset, sizeToInvalidate,
                          None);
    alignedAddr += NUM_OF_BYTES_PER_ADDRESS;
    i -= alignmentOffset;
    alignmentOffset = 0;
  }

  this->dump();
}

void crash_analyzer::MemoryWrapper::dump() {

  LLVM_DEBUG(for (auto MA = this->ChangedMemoryAddresses.begin(),
                  ME = this->ChangedMemoryAddresses.end();
                  MA != ME; MA++) {
    for (uint32_t i = 0; i < NUM_OF_BYTES_PER_ADDRESS; i++) {
      Optional<uint64_t> OptVal = None;
      if (MA->second.first & (1 << i))
        OptVal = (uint8_t)((MA->second.second & (0xFFUL << i * 8)) >> i * 8);
      if (OptVal)
        dumpOneMemoryLocation("\tValid location", MA->first + i, 1, OptVal);
      else
        dumpOneMemoryLocation("\tInvalid location", MA->first + i, 1, OptVal);
    }
  });
}