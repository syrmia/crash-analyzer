//===- ConcreteReverseExec.cpp - Concrete Reverse Execution ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/ConcreteReverseExec.h"

#include <iomanip>
#include <set>
#include <sstream>

#define DEBUG_TYPE "conrecete-rev-exec"

static cl::opt<bool> DisableCRE("disable-cre",
                                cl::desc("Disable Concrete Reverse Execution."),
                                cl::init(false));

void ConcreteReverseExec::dump() {
  LLVM_DEBUG(
      llvm::dbgs() << "\n****Concrete Register Values For Function: "
                   << mf->getName() << "\n";
      if (CurrentRegisterValues) {
        for (const auto &R : *CurrentRegisterValues) {
          if (R.Value != "")
            llvm::dbgs() << R.Name << ": " << R.Value << "\n";
          else
            llvm::dbgs() << R.Name << ": "
                         << "<not available>\n";
        }
      } else { llvm::dbgs() << "No register values specified in CRE\n"; });
}

void ConcreteReverseExec::dump2() {
  llvm::dbgs() << "\n****Concrete Register Values For Function: "
               << mf->getName() << "\n";
  for (const auto &R : *CurrentRegisterValues) {
    if (R.Value != "")
      llvm::dbgs() << R.Name << ": " << R.Value << "\n";
    else
      llvm::dbgs() << R.Name << ": "
                   << "<not available>\n";
  }
}

bool ConcreteReverseExec::getIsCREEnabled() const {
  if (DisableCRE)
    return false;
  return CREEnabled;
}

// TODO: Optimize this.
void ConcreteReverseExec::updateCurrRegVal(std::string Reg, std::string Val) {
  for (auto &R : *CurrentRegisterValues) {
    if (R.Name == Reg) {
      if (Val == "") {
        R.Value = "";
        return;
      }

      // Register value is unknown.
      if (R.Value == "") {
        if (CATI->getRegSize(Reg) == 64) {
          const unsigned RegValInBits = (Val.size() - 2) / 2 * 8;
          if (RegValInBits <= 64)
            R.Value = Val;
          else {
            // drop 0x
            Val.erase(Val.begin());
            Val.erase(Val.begin());
            // get last 8 bytes.
            R.Value = "0x" + Val.substr(/*8 bytes*/ Val.size() - 16);
          }
        } else if (CATI->getRegSize(Reg) == 32) {
          const unsigned RegValInBits = (Val.size() - 2) / 2 * 8;
          if (RegValInBits <= 32)
            R.Value = Val;
          else {
            // drop 0x
            Val.erase(Val.begin());
            Val.erase(Val.begin());
            // get last 4 bytes.
            R.Value = "0x" + Val.substr(/*4 bytes*/ Val.size() - 8);
          }
        } else if (CATI->getRegSize(Reg) == 16) {
          const unsigned RegValInBits = (Val.size() - 2) / 2 * 8;
          if (RegValInBits <= 16)
            R.Value = Val;
          else {
            // drop 0x
            Val.erase(Val.begin());
            Val.erase(Val.begin());
            // get last 2 bytes.
            R.Value = "0x" + Val.substr(/*2 bytes*/ Val.size() - 4);
          }
        } else if (CATI->getRegSize(Reg) == 8 && *Reg.rbegin() == 'l') {
          const unsigned RegValInBits = (Val.size() - 2) / 2 * 8;
          if (RegValInBits <= 8)
            R.Value = Val;
          else {
            // drop 0x
            Val.erase(Val.begin());
            Val.erase(Val.begin());
            // get last 2 bytes
            R.Value = "0x" + Val.substr(/*1 byte*/ Val.size() - 2);
          }
        }
        return;
      }

      // There is already a value that needs to be updated.
      if (R.Value.size() == Val.size())
        R.Value = Val;
      else if (R.Value.size() > Val.size()) {
        // drop 0x part.
        Val.erase(Val.begin());
        Val.erase(Val.begin());
        unsigned diff = R.Value.size() - Val.size();
        R.Value.replace(diff, Val.size(), Val);
      } else {
        // Val.size > R.Value.size
        // get the last N chars only:
        //  eax = 0x00000009
        //  ax = 0x0009
        Val.erase(Val.begin());
        Val.erase(Val.begin());
        unsigned diff = Val.size() - R.Value.size() + 2;
        R.Value = "0x" + Val.substr(diff);
      }
      return;
    }
  }
}

std::string ConcreteReverseExec::getCurretValueInReg(const std::string &Reg) {
  for (auto &R : *CurrentRegisterValues) {
    if (R.Name == Reg)
      return R.Value;
  }
  return std::string("");
}

template <typename T> std::string intToHex(T num, unsigned regValSize) {
  std::stringstream stream;
  stream << "0x" << std::setfill('0') << std::setw(regValSize) << std::hex
         << num;
  return stream.str();
}

void ConcreteReverseExec::writeUIntRegVal(std::string RegName, uint64_t Val,
                                          unsigned regValSize) {
  // We should update all reg aliases as well.
  // TODO: Improve this.
  auto regInfoId = CATI->getID(RegName);
  if (!regInfoId) {
    updateCurrRegVal(RegName, "");
    return;
  }
  auto RegsTuple = CATI->getRegMap(*regInfoId);
  // Create hex value with 16 chars.
  std::string newValue = intToHex(Val, regValSize);
  // update reg aliases as well.
  // e.g. if $eax is modified, update both $rax and $ax as well.
  updateCurrRegVal(std::get<0>(RegsTuple), newValue);
  updateCurrRegVal(std::get<1>(RegsTuple), newValue);
  updateCurrRegVal(std::get<2>(RegsTuple), newValue);
  updateCurrRegVal(std::get<3>(RegsTuple), newValue);
}

void ConcreteReverseExec::invalidateRegVal(std::string RegName) {
  // We should update all reg aliases as well.
  auto regInfoId = CATI->getID(RegName);
  if (!regInfoId) {
    updateCurrRegVal(RegName, "");
    return;
  }
  auto RegsTuple = CATI->getRegMap(*regInfoId);
  updateCurrRegVal(std::get<0>(RegsTuple), "");
  updateCurrRegVal(std::get<1>(RegsTuple), "");
  updateCurrRegVal(std::get<2>(RegsTuple), "");
  updateCurrRegVal(std::get<3>(RegsTuple), "");
}

void ConcreteReverseExec::updatePC(const MachineInstr &MI) {
  // If the option is enabled, we skip the CRE of the MIs.
  if (!getIsCREEnabled())
    return;
  // Initial PC value for the frame, points to the crash-start instruction.
  // We start updating PC for instructions preceding to the crash-start.
  if (MI.getFlag(MachineInstr::CrashStart))
    return;

  if (!CATI->getPC())
    return;
  std::string RegName = *CATI->getPC();

  if (!CATI->getInstAddr(&MI)) {
    invalidateRegVal(RegName);
    return;
  }
  uint64_t Val = 0;
  // Get MIs PC value saved during decompilation.
  Val = *CATI->getInstAddr(&MI);

  // Write current value of the register in the map.
  writeUIntRegVal(RegName, Val);
  dump();
}

std::string ConcreteReverseExec::getEqRegValue(MachineInstr *MI, Register &Reg,
                                               const TargetInstrInfo &TII,
                                               const TargetRegisterInfo &TRI) {
  std::string RetVal = "";

  auto &MRI = MI->getMF()->getRegInfo();

  if (REAnalysis) {
    auto EqRegisters = REAnalysis->getEqRegsAfterMI(MI, {Reg});
    for (auto &RegOffset : EqRegisters) {
      if (RegOffset.RegNum == Reg.id())
        continue;
      if (RegOffset.IsDeref) {
        std::string BaseStr = "";
        // rip register
        if (RegOffset.RegNum == 0)
          BaseStr = "0";
        else {
          std::string EqRegName = TRI.getRegAsmName(RegOffset.RegNum).lower();
          BaseStr = getCurretValueInReg(EqRegName);
        }

        if (BaseStr != "") {
          uint64_t BaseAddr = 0;
          std::stringstream SS;
          SS << std::hex << BaseStr;
          SS >> BaseAddr;

          BaseAddr += RegOffset.Offset;
          lldb::SBError error;
          // TO DO: Check if this is right
          uint32_t bitSize = TRI.getRegSizeInBits(Reg, MRI);
          uint32_t byteSize = bitSize / 8 + (bitSize % 8 ? 1 : 0);
          auto ValOpt =
              MemWrapper.ReadUnsignedFromMemory(BaseAddr, byteSize, error);
          if (ValOpt.hasValue()) {
            SS.clear();
            SS << std::hex << *ValOpt;
            SS >> RetVal;
            RetVal = "0x" + RetVal;
            break;
          }
        }
      } else {
        std::string EqRegName = TRI.getRegAsmName(RegOffset.RegNum).lower();
        RetVal = getCurretValueInReg(EqRegName);
        if (RegOffset.Offset) {
          uint64_t RetValNum = 0;
          std::istringstream(RetVal) >> std::hex >> RetValNum;
          RetValNum += RegOffset.Offset;
          std::stringstream SS;
          SS << std::hex << RetValNum;
          SS >> RetVal;
          RetVal = "0x" + RetVal;
        }
        if (RetVal != "")
          break;
      }
    }
    // Recursive get of value for ex. rax = (rax)+off, developing phase
    // Used for structs, works only on O0 - without optimizations
    if (RetVal == "") {
      auto OptDestSrc = TII.getDestAndSrc(*MI);
      if (MI->getParent()->begin() != MI->getIterator() &&
          OptDestSrc.hasValue()) {
        auto DestSrc = *OptDestSrc;
        if (DestSrc.Source->isReg() && DestSrc.SrcOffset.hasValue() &&
            DestSrc.Destination->isReg() && !DestSrc.DestOffset.hasValue() &&
            DestSrc.Source->getReg() == DestSrc.Destination->getReg()) {
          auto BaseStr =
              getEqRegValue(&*std::prev(MI->getIterator()), Reg, TII, TRI);
          if (BaseStr != "") {
            uint64_t BaseAddr = 0;
            std::stringstream SS;
            SS << std::hex << BaseStr;
            SS >> BaseAddr;
            BaseAddr += *DestSrc.SrcOffset;
            lldb::SBError err;
            uint32_t bitSize = TRI.getRegSizeInBits(Reg, MRI);
            uint32_t byteSize = bitSize / 8 + (bitSize % 8 ? 1 : 0);
            auto ValOpt =
                MemWrapper.ReadUnsignedFromMemory(BaseAddr, byteSize, err);
            if (ValOpt.hasValue()) {
              SS.clear();
              SS << std::hex << *ValOpt;
              SS >> RetVal;
              RetVal = "0x" + RetVal;
              // llvm::dbgs() << BaseStr << ":" << RetVal << "\n";
            }
          }
        }
      }
    }
  }

  return RetVal;
}

Optional<uint64_t> ConcreteReverseExec::extractValueOfOperand(
    const MachineInstr &MI, const MachineOperand *MO,
    const TargetInstrInfo *TII, const TargetRegisterInfo *TRI) {
  if (MO->isReg()) {
    auto Reg = MO->getReg();
    std::string RegName = TRI->getRegAsmName(Reg).lower();
    auto ValStr = getCurretValueInReg(RegName);
    uint64_t Val = 0;
    if (ValStr == "") {
      ValStr =
          getEqRegValue(const_cast<MachineInstr *>(&MI), {Reg}, *TII, *TRI);
      // We could return the value to the register!
      if (ValStr != "") {
        std::istringstream(ValStr) >> std::hex >> Val;
        writeUIntRegVal(RegName, Val, ValStr.size() - 2);
      }
    }
    if (ValStr != "") {
      std::istringstream(ValStr) >> std::hex >> Val;
      return Val;
    }
  } else if (MO->isImm()) {
    return static_cast<uint64_t>(MO->getImm());
  }
  return None;
}

Optional<uint64_t> ConcreteReverseExec::extractPreviousValueFromRegEq(
    const MachineInstr &MI, Register Reg, const TargetInstrInfo *TII,
    const TargetRegisterInfo *TRI) {
  // TO DO: Machine Instr at the beginning of basic block
  if (MI.getIterator() != MI.getParent()->begin()) {
    // TO DO: Check if this is right in all situations
    auto StrVal =
        getEqRegValue(const_cast<MachineInstr *>(&*std::prev(MI.getIterator())),
                      Reg, *TII, *TRI);
    if (StrVal == "")
      return None;
    else {
      uint64_t Val = 0;
      std::istringstream(StrVal) >> std::hex >> Val;
      return Val;
    }
  }
  return None;
}

bool ConcreteReverseExec::areRegsAliases(const Register R1, const Register R2,
                                         const TargetRegisterInfo *TRI) {
  for (MCRegAliasIterator RAI(R1, TRI, true); RAI.isValid(); ++RAI) {
    if ((*RAI).id() == R2.id())
      return true;
  }
  return false;
}

void ConcreteReverseExec::pcRegisterAddressFixup(const MachineInstr &MI,
                                                 std::string &RegName,
                                                 uint64_t &Addr) {
  if (CATI->isPCRegister(RegName)) {
    auto InstSize = CATI->getInstSize(&MI);
    // Crash analyzer could probably work without this assertion so change it to
    // if else if necessary
    assert(InstSize.hasValue() && "Couldn't get size of instruction");
    Addr += *InstSize;
  }
}

void ConcreteReverseExec::executePush(const MachineInstr &MI,
                                      DestSourcePair &DestSrc,
                                      const TargetInstrInfo *TII,
                                      const TargetRegisterInfo *TRI) {
  if (DestSrc.Destination && DestSrc.Destination->isReg()) {
    auto Reg = DestSrc.Destination->getReg();
    std::string RegName = TRI->getRegAsmName(Reg).lower();

    auto OptAddr = extractValueOfOperand(MI, DestSrc.Destination, TII, TRI);
    if (OptAddr) {
      uint64_t Addr = *OptAddr;
      if (DestSrc.DestOffset.hasValue()) {

        // Stack is already aligned on its address
        LLVM_DEBUG(llvm::dbgs()
                       << "Push instruction: " << MI << ", Destination: "
                       << "(" << RegName << ")"
                       << "+" << *DestSrc.DestOffset << "\n";);
        lldb::SBError error;
        // invalidate 8 bytes if size of instruction is not known
        uint32_t byteSize = 8;

        Optional<uint32_t> BitSize = TII->getBitSizeOfMemoryDestination(MI);
        if (BitSize.hasValue()) {
          // TO DO: Check if this is right
          byteSize = (*BitSize) / 8 + (*BitSize % 8 ? 1 : 0);
        }

        Optional<uint64_t> MemValOptional =
            MemWrapper.ReadUnsignedFromMemory(Addr, byteSize, error);
        LLVM_DEBUG(llvm::dbgs() << error.GetCString() << "\n";);
        if (MemValOptional.hasValue() && DestSrc.Source &&
            DestSrc.Source->isReg()) {
          uint64_t MemVal = *MemValOptional;
          std::string SrcRegName =
              TRI->getRegAsmName(DestSrc.Source->getReg()).lower();
          writeUIntRegVal(SrcRegName, MemVal, byteSize * 2);
          // 64 bit sp for x86
          writeUIntRegVal(RegName, Addr - (*DestSrc.DestOffset));
        }

        MemWrapper.InvalidateAddress(Addr, byteSize);
        dump();
      }
    }
  }
}

void ConcreteReverseExec::executeStore(const MachineInstr &MI,
                                       DestSourcePair &DestSrc,
                                       const TargetInstrInfo *TII,
                                       const TargetRegisterInfo *TRI) {
  if (DestSrc.Destination && DestSrc.Destination->isReg()) {
    auto Reg = DestSrc.Destination->getReg();
    std::string RegName = TRI->getRegAsmName(Reg).lower();

    auto OptAddr = extractValueOfOperand(MI, DestSrc.Destination, TII, TRI);
    if (OptAddr) {
      uint64_t Addr = *OptAddr;
      if (DestSrc.DestOffset) {

        Addr += static_cast<uint64_t>(*DestSrc.DestOffset);
        LLVM_DEBUG(llvm::dbgs()
                       << "Store instruction: " << MI << ", Destination: "
                       << "(" << RegName << ")"
                       << "+" << *DestSrc.DestOffset << "\n";);

        lldb::SBError error;
        // invalidate 8 bytes if size of instruction is not known
        uint32_t byteSize = 8;

        Optional<uint32_t> BitSize = TII->getBitSizeOfMemoryDestination(MI);
        if (BitSize) {
          // TO DO: Check if this is right
          byteSize = (*BitSize) / 8 + (*BitSize % 8 ? 1 : 0);
        }

        pcRegisterAddressFixup(MI, RegName, Addr);

        Optional<uint64_t> MemValOptional =
            MemWrapper.ReadUnsignedFromMemory(Addr, byteSize, error);
        LLVM_DEBUG(llvm::dbgs() << error.GetCString() << "\n";);
        if (MemValOptional.hasValue() && DestSrc.Source &&
            DestSrc.Source->isReg()) {
          uint64_t MemVal = *MemValOptional;
          std::string SrcRegName =
              TRI->getRegAsmName(DestSrc.Source->getReg()).lower();
          writeUIntRegVal(SrcRegName, MemVal, byteSize * 2);
        }
        MemWrapper.InvalidateAddress(Addr, byteSize);
        dump();
      }
    }
  }
}

void ConcreteReverseExec::executeAdd(const MachineInstr &MI,
                                     DestSourcePair &DestSrc,
                                     const TargetInstrInfo *TII,
                                     const TargetRegisterInfo *TRI,
                                     const MachineRegisterInfo &MRI, int Sign) {
  if (DestSrc.Destination && DestSrc.Destination->isReg()) {
    auto DestReg = DestSrc.Destination->getReg();
    std::string DestRegName = TRI->getRegAsmName(DestReg).lower();

    uint64_t SrcVal = 0;
    uint64_t DestVal = 0;
    Optional<uint64_t> OptSrcVal = None;
    Optional<uint64_t> OptDestVal =
        extractValueOfOperand(MI, DestSrc.Destination, TII, TRI);
    std::string SrcRegName = "";
    // Source2 is there only if it is an immediate, on X86 implementation for
    // now
    if (!DestSrc.Source2 && DestSrc.Source && DestSrc.Source->isReg()) {
      auto SrcReg = DestSrc.Source->getReg();
      SrcRegName = TRI->getRegAsmName(SrcReg).lower();
      OptSrcVal = extractValueOfOperand(MI, DestSrc.Source, TII, TRI);

      // Cannot know value of reg if adding to reg from reg,
      // unless RegisterEquivalence has some equivalent registers
      // TODO: Add the case when adding reg to same reg ( 2 * reg )
      bool SrcDestMatch = areRegsAliases(DestReg, SrcReg, TRI);
      if (!DestSrc.DestOffset && SrcDestMatch) {
        OptSrcVal = extractPreviousValueFromRegEq(MI, SrcReg, TII, TRI);
      }
    } else if (DestSrc.Source2 && DestSrc.Source2->isImm()) {
      // empty reg name is because its not needed when extracting an immediate
      OptSrcVal = extractValueOfOperand(MI, DestSrc.Source2, TII, TRI);
    }
    if (OptSrcVal && OptDestVal) {
      SrcVal = *OptSrcVal;
      DestVal = *OptDestVal;

      // Source is memory, then Dest is definitely a Register
      if (DestSrc.SrcOffset && !DestSrc.Source2) {
        // SrcVal is now the address
        SrcVal += *DestSrc.SrcOffset;
        pcRegisterAddressFixup(MI, SrcRegName, SrcVal);
        // TO DO: Check if this is right
        uint32_t bitSize = TRI->getRegSizeInBits(DestReg, MRI);
        uint32_t byteSize = bitSize / 8 + (bitSize % 8 ? 1 : 0);
        lldb::SBError error;
        OptSrcVal = MemWrapper.ReadUnsignedFromMemory(SrcVal, byteSize, error);
        LLVM_DEBUG(llvm::dbgs() << error.GetCString() << "\n";);
        if (OptSrcVal) {
          DestVal -= Sign * (*OptSrcVal);
          writeUIntRegVal(DestRegName, DestVal, byteSize * 2);
          return;
        }
      }
      // Dest is memory, source is Reg or Immediate
      else if (DestSrc.DestOffset) {
        DestVal += *DestSrc.DestOffset;
        pcRegisterAddressFixup(MI, DestRegName, DestVal);
        // TO DO: Check if this is right
        // byteSize is 8 at first if we cannot determine the size of mem dest
        uint32_t byteSize = 8;
        auto OptBitSize = TII->getBitSizeOfMemoryDestination(MI);
        if (OptBitSize) {
          byteSize = *OptBitSize / 8 + (*OptBitSize % 8 ? 1 : 0);
        }
        lldb::SBError error;
        uint64_t Addr = DestVal;
        OptDestVal = MemWrapper.ReadUnsignedFromMemory(Addr, byteSize, error);
        LLVM_DEBUG(llvm::dbgs() << error.GetCString() << "\n";);
        if (OptDestVal) {
          DestVal = *OptDestVal;
          DestVal -= Sign * SrcVal;
          MemWrapper.WriteMemory(Addr, &DestVal, byteSize, error);
          return;
        }

      }
      // Neither Dest nor Source are Mem, Dest is Reg
      else {
        DestVal -= Sign * SrcVal;
        // TO DO: Check if this is right
        uint32_t bitSize = TRI->getRegSizeInBits(DestReg, MRI);
        uint32_t byteSize = bitSize / 8 + (bitSize % 8 ? 1 : 0);
        writeUIntRegVal(DestRegName, DestVal, byteSize * 2);
        return;
      }
    }
    invalidateRegVal(DestRegName);
  }
}

// Add implementation for conversion operations ( 32 bit to 64  bit )
void ConcreteReverseExec::executeLoad(const MachineInstr &MI,
                                      DestSourcePair &DestSrc,
                                      const TargetInstrInfo *TII,
                                      const TargetRegisterInfo *TRI,
                                      const MachineRegisterInfo &MRI) {
  LLVM_DEBUG(llvm::dbgs() << "Load instruction: " << MI;);
  auto DestReg = DestSrc.Destination->getReg();
  std::string DestRegName = TRI->getRegAsmName(DestReg).lower();

  uint64_t DestVal = 0;
  Optional<uint64_t> OptDestVal = None;
  uint64_t SrcVal = 0;
  Optional<uint64_t> OptSrcVal = None;
  OptDestVal = extractValueOfOperand(MI, DestSrc.Destination, TII, TRI);
  if (!OptDestVal)
    return;
  // Once we got the value we can invalidate the loaded register
  invalidateRegVal(DestRegName);
  DestVal = *OptDestVal;

  if (DestSrc.Source && DestSrc.SrcOffset) {
    auto SrcReg = DestSrc.Source->getReg();
    std::string SrcRegName = TRI->getRegAsmName(SrcReg).lower();

    bool SrcDestMatch = areRegsAliases(DestReg, SrcReg, TRI);
    // Cannot know value of memory if loading reg from (reg)offset,
    // unless RegisterEquivalence has some equivalent registers,
    // from previous instructions
    if (SrcDestMatch) {
      OptSrcVal = extractPreviousValueFromRegEq(MI, SrcReg, TII, TRI);
    } else {
      OptSrcVal = extractValueOfOperand(MI, DestSrc.Source, TII, TRI);
    }

    if (!OptSrcVal)
      return;
    //  Calculating memory address
    SrcVal = *OptSrcVal;
    uint64_t PrevVal = SrcVal;
    SrcVal += *DestSrc.SrcOffset;

    pcRegisterAddressFixup(MI, SrcRegName, SrcVal);

    uint32_t BitSize =
        TRI->getRegSizeInBits(DestSrc.Destination->getReg(), MRI);
    uint32_t ByteSize = BitSize / 8 + (BitSize % 8 ? 1 : 0);

    auto OptSrcMemSize = TII->getBitSizeOfMemorySource(MI);

    lldb::SBError error;
    // This is necessary for extenstion load instructions (MOVSX on x86)
    if (OptSrcMemSize) {
      uint32_t SrcBitSize = *OptSrcMemSize / 8 + (*OptSrcMemSize % 8 ? 1 : 0);
      MemWrapper.WriteMemory(SrcVal, &DestVal, SrcBitSize, error);
    } else
      MemWrapper.WriteMemory(SrcVal, &DestVal, ByteSize, error);
    // No chance of error, it is just there for the function call
    // We know prev reg value, we can return it
    if (SrcReg == DestReg) {
      writeUIntRegVal(SrcRegName, PrevVal, ByteSize * 2);
    }
  }
}

/*
void ConcreteReverseExec::executeAddToMem(const MachineInstr &MI, DestSourcePair
&DestSrc, const TargetInstrInfo *TII, const TargetRegisterInfo *TRI, int Sign)
{
  if (DestSrc.Destination) {
      auto Reg = DestSrc.Destination->getReg();
      uint64_t SrcVal = 0;
      uint64_t DestVal = 0;
      Optional<uint64_t> OptSrcVal = None;

      std::string RegName = TRI->getRegAsmName(Reg).lower();
      // Source2 is there only if it is an immediate
      if (!DestSrc.Source2 && DestSrc.Source && DestSrc.Source->isReg()) {
        auto SrcReg = DestSrc.Source->getReg();
        std::string SrcRegName = TRI->getRegAsmName(SrcReg).lower();
        OptSrcVal = extractValueOfOperand(MI, DestSrc.Source, TII, TRI, SrcReg,
SrcRegName); } else if (DestSrc.Source2 && DestSrc.Source2->isImm()) {
        // no need for register and reg name as it is an immediate
        OptSrcVal = extractValueOfOperand(MI, DestSrc.Source2, TII, TRI, 0, "");
      }

      auto OptAddr = extractValueOfOperand(MI, DestSrc.Destination, TII, TRI,
Reg, RegName);

      if (OptAddr && OptSrcVal) {
        SrcVal = *OptSrcVal;
        uint64_t Addr = *OptAddr;
        Addr += *DestSrc.DestOffset;
        LLVM_DEBUG(llvm::dbgs()
                   << "Add memory instruction: " << MI << " Destination: "
                   << "(" << RegName << ")"
                   << "+" << *DestSrc.DestOffset << "\n");

        pcRegisterAddressFixup(MI, RegName, Addr);

        lldb::SBError error;
        // invalidate 8 bytes if size of instruction is not known
        uint32_t byteSize = 8;

        Optional<uint32_t> BitSize = TII->getBitSizeOfMemoryDestination(MI);
        if (BitSize.hasValue()) {
          // TO DO: Check if this is right
          byteSize = (*BitSize) / 8 + (*BitSize % 8 ? 1 : 0);
        }

        auto MemValOptional =
            MemWrapper.ReadUnsignedFromMemory(Addr, byteSize, error);
        LLVM_DEBUG(llvm::dbgs() << error.GetCString() << "\n";);
        if (MemValOptional.hasValue()) {
          DestVal = *MemValOptional;
          DestVal -= Sign * SrcVal;
          MemWrapper.WriteMemory(Addr, &DestVal, byteSize, error);
        }
        dump();
      }
    }
}

bool ConcreteReverseExec::executeAddToReg(const MachineInstr &MI, DestSourcePair
&DestSrc, const TargetInstrInfo *TII, const TargetRegisterInfo *TRI, const
MachineRegisterInfo &MRI, int Sign)
{
  auto Reg = DestSrc.Destination->getReg();
  std::string RegName = TRI->getRegAsmName(Reg).lower();
  uint64_t Val = 0;
  auto OptVal = extractValueOfOperand(MI, DestSrc.Destination, TII, TRI, Reg,
RegName); if(OptVal)
  {
    Val = *OptVal;
  }
  else {
    return true;
  }
  uint32_t bitSize = TRI->getRegSizeInBits(Reg, MRI);
  uint32_t byteSize = (bitSize / 8) + (bitSize % 8 ? 1 : 0);
  Optional<uint64_t> OptSrcVal = None;
  std::string SrcRegStr = "";
  Register SrcReg = 0;
  // Source2 is there only if it is an immediate
  if (DestSrc.Source && DestSrc.Source->isReg() && !DestSrc.Source2) {
    SrcReg = DestSrc.Source->getReg();
    SrcRegStr = TRI->getRegAsmName(SrcReg).lower();
    OptSrcVal = extractValueOfOperand(MI, DestSrc.Source, TII, TRI, SrcReg,
SrcRegStr);

    // Cannot know value of memory if adding to reg from reg,
    // unless RegisterEquivalence has some equivalent registers
    // TODO: Add the case when adding reg to same reg ( 2 * reg )
    if (DestSrc.Source->getReg() == Reg) {
      // TO DO: Machine Instr at the beginning of basic block
      if (MI.getIterator() != MI.getParent()->begin()) {
        OptSrcVal = extractValueOfOperand(*std::prev(&MI), DestSrc.Source, TII,
TRI, SrcReg, SrcRegStr); if (!OptSrcVal) { invalidateRegVal(RegName); dump();
          return true;
        }
      } else {
        invalidateRegVal(RegName);
        dump();
        return true;
      }
    }
    else if(!OptSrcVal)
    {
      invalidateRegVal(RegName);
      dump();
      return true;
    }
  }
  else if(DestSrc.Source2 && DestSrc.Source2->isImm())
  {
    // empty reg name is because its not needed when extracting an immediate
    OptSrcVal = extractValueOfOperand(MI, DestSrc.Source2, TII, TRI, 0, "");
  }
  uint64_t SrcVal = *OptSrcVal;
  // add reg to reg
  if (!DestSrc.SrcOffset) {
    Val -= Sign * SrcVal;
    writeUIntRegVal(RegName, Val, byteSize * 2);
    dump();
    return true;
  }
  // add reg ind mem to reg
  else {
    uint64_t Addr = SrcVal;
    Addr += static_cast<uint64_t>(*DestSrc.SrcOffset);
    pcRegisterAddressFixup(MI, SrcRegStr, Addr);

    // TO DO: Check if this is right
    uint32_t bitSize =
        TRI->getRegSizeInBits(DestSrc.Destination->getReg(), MRI);
    uint32_t byteSize = bitSize / 8 + (bitSize % 8 ? 1 : 0);

    lldb::SBError error;
    auto MemVal =
        MemWrapper.ReadUnsignedFromMemory(Addr, byteSize, error);
    if (MemVal) {
      Val -= Sign * (*MemVal);
      writeUIntRegVal(RegName, Val, byteSize * 2);
      dump();
      return true;
    } else {
      invalidateRegVal(RegName);
      dump();
      return true;
    }
  }
  return false;
}
*/
// TODO: Alias registers on some places
void ConcreteReverseExec::execute(const MachineInstr &MI) {
  // If the option is enabled, we skip the CRE of the MIs.
  if (!getIsCREEnabled())
    return;

  // If this instruction modifies any of the registers,
  // update the register values for the function. First definition of the reg
  // is the one that is in the 'regInfo:' (going backward is the first, but it
  // is the latest def actually by going forward).
  auto TRI = MI.getParent()->getParent()->getSubtarget().getRegisterInfo();
  auto TII = MI.getParent()->getParent()->getSubtarget().getInstrInfo();

  auto &MRI = MI.getMF()->getRegInfo();
  // This will be used to avoid implicit operands that can be in the instruction
  // multiple times.
  std::multiset<Register> RegisterWorkList;
  int Sign = 0;
  auto OptDestSrc = TII->getDestAndSrc(MI);

  if (OptDestSrc.hasValue()) {
    DestSourcePair &DestSrc = *OptDestSrc;
    if (TII->isStore(MI)) {
      executeStore(MI, DestSrc, TII, TRI);
    } else if (TII->isPush(MI)) {
      executePush(MI, DestSrc, TII, TRI);
    }
    // Add to mem instructions
    // To add more support for AddToDest change
    // X86TargetInstrInfo::isAddToDest function
    // along with getDestAndSrc function to
    // support more instructions
    else if (DestSrc.DestOffset &&
             (Sign = TII->isAddToDest(
                  MI, const_cast<MachineOperand *>(DestSrc.Destination),
                  DestSrc.DestOffset))) {
      executeAdd(MI, DestSrc, TII, TRI, MRI, Sign);
    }
  }

  for (const MachineOperand &MO : MI.operands()) {
    if (!MO.isReg())
      continue;
    Register Reg = MO.getReg();
    RegisterWorkList.insert(Reg);
    std::string RegName = TRI->getRegAsmName(Reg).lower();

    // change register only once
    if (RegisterWorkList.count(Reg) == 1 && MI.modifiesRegister(Reg, TRI)) {
      LLVM_DEBUG(llvm::dbgs() << MI << " modifies " << RegName << "\n";);
      // Here we update the register values.

      // TODO: Handle all posible opcodes here.
      // For all unsupported MIs, we just invalidates the value in reg
      // by setting it to "".

      // If the value of the register isn't available, we have nothing to
      // update.
      // FIXME: Is this right?
      auto regVal = getCurretValueInReg(RegName);
      if (regVal == "") {
        continue;
      }

      // Skip push/pop intructions here.
      if (TII->isPush(MI) || TII->isPop(MI))
        continue;

      // uint64_t Val = 0;
      // std::stringstream SS;
      // SS << std::hex << regVal;
      // SS >> Val;

      if (OptDestSrc) {
        DestSourcePair &DestSrc = *OptDestSrc;
        if (TII->isLoad(MI) && !DestSrc.DestOffset && DestSrc.Destination &&
            DestSrc.Destination->isReg() &&
            DestSrc.Destination->getReg() == MO.getReg()) {
          executeLoad(MI, DestSrc, TII, TRI, MRI);
          dump();
          continue;
        }
        // In c_test_cases/test3.c there is a case
        //  $eax = ADD32ri8 $eax(tied-def 0), 1
        // so handle it.
        // To add more support for AddToDest change
        // X86TargetInstrInfo::isAddToDest function
        // along with getDestAndSrc function to
        // support more instructions
        else if (!DestSrc.DestOffset &&
                 (Sign = TII->isAddToDest(MI, const_cast<MachineOperand *>(&MO),
                                          DestSrc.DestOffset))) {
          executeAdd(MI, DestSrc, TII, TRI, MRI, Sign);
          dump();
          continue;
        } else {
          LLVM_DEBUG(llvm::dbgs() << "Concrete Rev Exec not supported for \n";
                     MI.dump(););
          invalidateRegVal(RegName);
          dump();
        }
      }
    }
  }
}
