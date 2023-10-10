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
            DestSrc.Source->getReg() == Reg) {
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

// TODO: Check alias registers
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

  if (OptDestSrc.hasValue() && (TII->isStore(MI) || TII->isPush(MI))) {
    DestSourcePair &DestSrc = *OptDestSrc;

    if (DestSrc.Destination) {
      auto Reg = DestSrc.Destination->getReg();
      std::string RegName = TRI->getRegAsmName(Reg).lower();

      auto AddrStr = getCurretValueInReg(RegName);
      if (AddrStr == "") {
        AddrStr =
            getEqRegValue(const_cast<MachineInstr *>(&MI), {Reg}, *TII, *TRI);
        // We could return the value to the register!
        if (AddrStr != "") {
          uint64_t Addr = 0;
          std::istringstream(AddrStr) >> std::hex >> Addr;

          writeUIntRegVal(RegName, Addr, AddrStr.size() - 2);
        }
      }

      if (AddrStr != "") {
        uint64_t Addr = 0;
        std::stringstream SS;
        SS << std::hex << AddrStr;
        SS >> Addr;
        if (DestSrc.DestOffset.hasValue()) {
          if (TII->isStore(MI)) {

            Addr += static_cast<uint64_t>(*DestSrc.DestOffset);
            LLVM_DEBUG(llvm::dbgs()
                           << "Store instruction: " << MI << ", Destination: "
                           << "(" << RegName << ")"
                           << "+" << *DestSrc.DestOffset << "\n";);

          } else if (TII->isPush(MI)) {
            // Stack is already aligned on its address
            LLVM_DEBUG(llvm::dbgs()
                           << "Push instruction: " << MI << ", Destination: "
                           << "(" << RegName << ")"
                           << "+" << *DestSrc.DestOffset << "\n";);
          }
          lldb::SBError error;
          // invalidate 8 bytes if size of instruction is not known
          uint32_t byteSize = 8;

          Optional<uint32_t> BitSize = TII->getBitSizeOfMemoryDestination(MI);
          if (BitSize.hasValue()) {
            // TO DO: Check if this is right
            byteSize = (*BitSize) / 8 + (*BitSize % 8 ? 1 : 0);
          }

          if (CATI->isPCRegister(RegName)) {
            auto InstSize = CATI->getInstSize(&MI);
            if (InstSize.hasValue()) {
              Addr += *InstSize;
            } else {
              // TO DO: Check if getInstSize returns None some times
              // Note: It has all insts up until crash-start
              LLVM_DEBUG(llvm::dbgs() << "Couldn't get size of instruction "
                                      << MI << "\n";);
            }
          }

          Optional<uint64_t> MemValOptional =
              MemWrapper.ReadUnsignedFromMemory(Addr, byteSize, error);
          LLVM_DEBUG(llvm::dbgs() << error.GetCString() << "\n";);
          if (MemValOptional.hasValue() && DestSrc.Source && !DestSrc.Source2) {
            if (!DestSrc.Src2Offset.hasValue() && DestSrc.Source->isReg()) {

              uint64_t MemVal = *MemValOptional;
              std::string SrcRegName =
                  TRI->getRegAsmName(DestSrc.Source->getReg()).lower();
              writeUIntRegVal(SrcRegName, MemVal, byteSize * 2);
            }
          }
          if (TII->isPush(MI)) {
            writeUIntRegVal(RegName, Addr - (*DestSrc.DestOffset),
                            AddrStr.size() - 2);
          }

          MemWrapper.InvalidateAddress(Addr, byteSize);
          dump();
        }
      }
    }
  }

  // Add to mem instructions
  // To add more support for AddToDest change
  // X86TargetInstrInfo::isAddToDest function
  // along with getDestAndSrc function to
  // support more instructions
  // Add implementation of add immediate to mem
  if (OptDestSrc.hasValue() && (*OptDestSrc).DestOffset.hasValue() &&
      (Sign = TII->isAddToDest(
           MI, const_cast<MachineOperand *>((*OptDestSrc).Destination),
           (*OptDestSrc).DestOffset))) {
    DestSourcePair &DestSrc = *OptDestSrc;
    if (DestSrc.Destination) {
      auto Reg = DestSrc.Destination->getReg();
      uint64_t SrcVal = 0;
      uint64_t DestVal = 0;

      std::string SrcValStr = "";
      std::string RegName = TRI->getRegAsmName(Reg).lower();
      if (DestSrc.Source->isReg()) {
        auto SrcReg = DestSrc.Source->getReg();
        std::string SrcRegName = TRI->getRegAsmName(SrcReg).lower();
        SrcValStr = getCurretValueInReg(SrcRegName);
        if (SrcValStr == "") {
          SrcValStr = getEqRegValue(const_cast<MachineInstr *>(&MI), SrcReg,
                                    *TII, *TRI);
        }
      } else if (DestSrc.Source->isImm()) {
        SrcVal = DestSrc.Source->getImm();
        // Just put something to pass the if statement afterwards
        SrcValStr = "1";
      }
      auto AddrStr = getCurretValueInReg(RegName);
      if (AddrStr == "") {
        AddrStr =
            getEqRegValue(const_cast<MachineInstr *>(&MI), Reg, *TII, *TRI);
      }

      if (AddrStr != "" && SrcValStr != "") {
        if (DestSrc.Source->isReg()) {
          std::istringstream(SrcValStr) >> std::hex >> SrcVal;
        }
        uint64_t Addr = 0;
        std::istringstream(AddrStr) >> std::hex >> Addr;
        Addr += *DestSrc.DestOffset;
        LLVM_DEBUG(llvm::dbgs()
                   << "Add memory instruction: " << MI << " Destination: "
                   << "(" << RegName << ")"
                   << "+" << *DestSrc.DestOffset << "\n");
        if (CATI->isPCRegister(RegName)) {
          auto InstSize = CATI->getInstSize(&MI);
          if (InstSize.hasValue()) {
            Addr += *InstSize;
          } else {
            // TO DO: Check if getInstSize returns None some times
            // Note: It has all insts up until crash-start
            LLVM_DEBUG(llvm::dbgs() << "Couldn't get size of instruction " << MI
                                    << "\n";);
          }
        }

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

  for (const MachineOperand &MO : MI.operands()) {
    if (!MO.isReg())
      continue;
    Register Reg = MO.getReg();
    RegisterWorkList.insert(Reg);
    std::string RegName = TRI->getRegAsmName(Reg).lower();

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
        // FIXME: No use of register equivalence here and it even shouldn't be
        // right, is this right? regVal =
        // getEqRegValue(const_cast<MachineInstr*>(&MI), Reg, *TRI); if(regVal
        // == "") continue;
        continue;
      }

      // Skip push/pop intructions here.
      if (TII->isPush(MI) || TII->isPop(MI))
        continue;

      uint64_t Val = 0;
      std::stringstream SS;
      SS << std::hex << regVal;
      SS >> Val;

      // In c_test_cases/test3.c there is a case
      //  $eax = ADD32ri8 $eax(tied-def 0), 1
      // so handle it.

      // To add more support for AddImmediate, change
      // X86TargetInstrInfo::isAddImmediate function
      // Now it also includes sub instrs, but not all
      // of them
      if (auto RegImm = TII->isAddImmediate(MI, Reg)) {
        if (RegImm->Reg == Reg) {
          // We do the oposite operation, since we are
          // intereting the instruction going backward.
          Val -= RegImm->Imm;
          // Write current value of the register in the map.
          writeUIntRegVal(RegName, Val, regVal.size() - 2);
          dump();
          continue;
        }
      }

      int Sign = 0;
      auto OptDestSrc = TII->getDestAndSrc(MI);
      // To add more support for AddToDest change
      // X86TargetInstrInfo::isAddToDest function
      // along with getDestAndSrc function to
      // support more instructions
      if (OptDestSrc.hasValue() && !(*OptDestSrc).DestOffset.hasValue() &&
          (Sign = TII->isAddToDest(MI, const_cast<MachineOperand *>(&MO),
                                   (*OptDestSrc).DestOffset))) {
        DestSourcePair &DestSrc = *OptDestSrc;

        if (DestSrc.Source && DestSrc.Source->isReg()) {
          Register SrcReg = DestSrc.Source->getReg();
          std::string SrcRegStr = TRI->getRegAsmName(SrcReg).lower();
          auto srcRegVal = getCurretValueInReg(SrcRegStr);
          if (srcRegVal == "") {
            srcRegVal = getEqRegValue(const_cast<MachineInstr *>(&MI), SrcReg,
                                      *TII, *TRI);
            if (srcRegVal == "") {
              invalidateRegVal(RegName);
              dump();
              continue;
            }
          }
          // Cannot know value of memory if adding to reg from reg,
          // unless RegisterEquivalence has some equivalent registers
          // TODO: Add the case when adding reg to same reg ( 2 * reg )
          if (DestSrc.Source->getReg() == Reg) {
            // TO DO: Machine Instr at the beginning of basic block
            if (MI.getIterator() != MI.getParent()->begin()) {
              srcRegVal = getEqRegValue(
                  const_cast<MachineInstr *>(&*std::prev(MI.getIterator())),
                  Reg, *TII, *TRI);
              if (srcRegVal == "") {
                invalidateRegVal(RegName);
                dump();
                continue;
              }
            } else {
              invalidateRegVal(RegName);
              dump();
              continue;
            }
          }

          // add reg to reg
          if (!DestSrc.SrcOffset.hasValue()) {
            uint64_t Delta = 0;
            std::istringstream(srcRegVal) >> std::hex >> Delta;
            Val -= Sign * Delta;
            writeUIntRegVal(RegName, Val, regVal.size() - 2);
            dump();
            continue;
          }
          // add reg ind mem to reg
          else {
            uint64_t Addr = 0;
            std::istringstream(srcRegVal) >> std::hex >> Addr;
            Addr += static_cast<uint64_t>(*DestSrc.SrcOffset);
            if (CATI->isPCRegister(SrcRegStr)) {
              // TODO: Test this, global addresses
              auto InstSize = CATI->getInstSize(&MI);
              if (InstSize.hasValue()) {
                Addr += *InstSize;
              } else {
                // TO DO: Check if getInstSize returns None some times
                LLVM_DEBUG(llvm::dbgs() << "Couldn't get size of instruction "
                                        << MI << "\n";);
                invalidateRegVal(RegName);
                dump();
                continue;
              }
            }

            // TO DO: Check if this is right
            uint32_t bitSize =
                TRI->getRegSizeInBits(DestSrc.Destination->getReg(), MRI);
            uint32_t byteSize = bitSize / 8 + (bitSize % 8 ? 1 : 0);

            lldb::SBError error;
            auto MemVal =
                MemWrapper.ReadUnsignedFromMemory(Addr, byteSize, error);
            if (MemVal.hasValue()) {
              Val -= Sign * (*MemVal);
              writeUIntRegVal(RegName, Val, regVal.size() - 2);
              dump();
              continue;
            } else {
              invalidateRegVal(RegName);
              dump();
              continue;
            }
          }
        }
      }

      if (OptDestSrc.hasValue() && TII->isLoad(MI)) {
        LLVM_DEBUG(llvm::dbgs() << "Load instruction: " << MI;);
        DestSourcePair &DestSrc = *OptDestSrc;

        if (DestSrc.Source && DestSrc.Source->isReg() &&
            DestSrc.SrcOffset.hasValue()) {
          Register SrcReg = DestSrc.Source->getReg();
          std::string SrcRegStr = TRI->getRegAsmName(SrcReg).lower();
          auto srcRegVal = getCurretValueInReg(SrcRegStr);
          if (srcRegVal == "") {
            srcRegVal = getEqRegValue(const_cast<MachineInstr *>(&MI), SrcReg,
                                      *TII, *TRI);
            if (srcRegVal == "") {
              invalidateRegVal(RegName);
              dump();
              continue;
            }
          }

          // Cannot know value of memory if loading reg from (reg)offset,
          // unless RegisterEquivalence has some equivalent registers
          if (DestSrc.Source->getReg() == Reg) {
            // TO DO: Machine Instr at the beginning of basic block
            if (MI.getIterator() != MI.getParent()->begin()) {
              // TO DO: Check if this is right in all situations
              srcRegVal = getEqRegValue(
                  const_cast<MachineInstr *>(&*std::prev(MI.getIterator())),
                  Reg, *TII, *TRI);
              if (srcRegVal == "") {
                invalidateRegVal(RegName);
                dump();
                continue;
              }
            } else {
              invalidateRegVal(RegName);
              dump();
              continue;
            }
          }

          uint64_t Addr;
          std::istringstream(srcRegVal) >> std::hex >> Addr;
          uint64_t PrevVal = Addr;
          Addr += static_cast<uint64_t>(*DestSrc.SrcOffset);
          if (CATI->isPCRegister(SrcRegStr)) {
            auto InstSize = CATI->getInstSize(&MI);
            if (InstSize.hasValue()) {
              Addr += *InstSize;
            } else {
              // TO DO: Check if getInstSize returns None some times
              LLVM_DEBUG(llvm::dbgs() << "Couldn't get size of instruction "
                                      << MI << "\n";);
              // We know prev reg val, because of reg eq
              if (DestSrc.Source->getReg() == Reg)
                writeUIntRegVal(RegName, PrevVal, regVal.size() - 2);
              else
                invalidateRegVal(RegName);
              dump();
              continue;
            }
          }
          // TO DO: Check if this is right
          uint32_t bitSize =
              TRI->getRegSizeInBits(DestSrc.Destination->getReg(), MRI);
          uint32_t byteSize = bitSize / 8 + (bitSize % 8 ? 1 : 0);

          lldb::SBError error;
          MemWrapper.WriteMemory(Addr, &Val, byteSize, error);
          // We know prev reg val, because of reg eq
          if (DestSrc.Source->getReg() == Reg)
            writeUIntRegVal(RegName, PrevVal, regVal.size() - 2);
          else
            invalidateRegVal(RegName);
          dump();
          continue;
        }
      }

      // FIXME: This isn't right, since current instruction shouldn't
      // be using the new value.
      /*else if (MI.isMoveImmediate()) {
       if (!MI.getOperand(1).isImm()) {
         updateCurrRegVal(RegName, "");
         return;
       }
       Val = MI.getOperand(1).getImm();
       std::stringstream SS;
       SS << std::hex << regVal;
       SS >> Val;
       // Write current value of the register in the map.
       writeUIntRegVal(RegName, Val, regVal.size() - 2);

       dump();
       return;
     }*/

      // The MI is not supported, so consider it as not available.
      LLVM_DEBUG(llvm::dbgs() << "Concrete Rev Exec not supported for \n";
                 MI.dump(););
      // Invalidate register value, since it is not available.
      invalidateRegVal(RegName);
      dump();
    }
  }
}
