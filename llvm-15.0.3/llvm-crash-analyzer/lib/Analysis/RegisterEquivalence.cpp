//===- RegisterEquivalence.cpp - Register Equivalence ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/RegisterEquivalence.h"

#include "llvm/ADT/PostOrderIterator.h"

#include <algorithm>
#include <deque>
#include <set>

#define DEBUG_TYPE "register-eq"

void RegisterEquivalence::init(MachineFunction &MF) {
  TRI = MF.getSubtarget().getRegisterInfo();
  TII = MF.getSubtarget().getInstrInfo();
}

void RegisterEquivalence::join(MachineBasicBlock &MBB,
                               RegisterEqSet &EqLocBeforeCurrMBB) {
  LLVM_DEBUG(llvm::dbgs() << "** join for bb." << MBB.getNumber() << "\n");

  // An indicator whether any predecessor was processed.
  bool PredecessorProcessed = false;

  SmallVector<MachineBasicBlock *, 8> Predecessors(MBB.pred_begin(),
                                                   MBB.pred_end());
  for (auto *PredBlock : Predecessors) {
    // If a predecessor hasn't been analyzed, skip it.
    auto EqLocAfterPredIter = EqLocAfterMBB.find(PredBlock->getNumber());
    if (EqLocAfterPredIter == EqLocAfterMBB.end()) {
      continue;
    }
    auto &EqLocAfterPred = EqLocAfterPredIter->second;
    LLVM_DEBUG(llvm::dbgs() << "pred bb." << PredBlock->getNumber() << ":\n");
    LLVM_DEBUG(dumpRegTable(EqLocAfterPred));

    // If no predecessor has been processed, just copy the set of equivalent
    // locations from a predecessor.
    if (!PredecessorProcessed) {
      EqLocBeforeCurrMBB = EqLocAfterPred;
      PredecessorProcessed = true;
    } else {
      // Go through all pairs of a location and a set of its equivalent
      // locations. Intersect the sets of the equivalent locations for a given
      // location, considering that any of the predecessors could be executed in
      // the runtime. During reverse execution it is generally unknown which
      // block was really a predecessor and that's why it is used intersection.
      // Discard empty sets.
      for (auto &regs : EqLocAfterPred) {
        RegisterOffsetPair reg{regs.first.RegNum, regs.first.Offset,
                               regs.first.IsDeref};
        if (EqLocBeforeCurrMBB.find(reg) != EqLocBeforeCurrMBB.end()) {
          std::set<RegisterOffsetPair> NewSet;
          std::set_intersection(
              EqLocBeforeCurrMBB[reg].begin(), EqLocBeforeCurrMBB[reg].end(),
              EqLocAfterPred[reg].begin(), EqLocAfterPred[reg].end(),
              std::inserter(NewSet, NewSet.begin()));
          if (NewSet.size() == 0) {
            EqLocBeforeCurrMBB.erase(reg);
          } else {
            EqLocBeforeCurrMBB[reg] = NewSet;
          }
        }
      }
      for (auto &regs : make_early_inc_range(EqLocBeforeCurrMBB)) {
        RegisterOffsetPair reg{regs.first.RegNum, regs.first.Offset,
                               regs.first.IsDeref};
        if (EqLocAfterPred.find(reg) != EqLocAfterPred.end()) {
          std::set<RegisterOffsetPair> NewSet;
          std::set_intersection(
              EqLocBeforeCurrMBB[reg].begin(), EqLocBeforeCurrMBB[reg].end(),
              EqLocAfterPred[reg].begin(), EqLocAfterPred[reg].end(),
              std::inserter(NewSet, NewSet.begin()));
          if (NewSet.size() == 0) {
            EqLocBeforeCurrMBB.erase(reg);
          } else {
            EqLocBeforeCurrMBB[reg] = NewSet;
          }
        } else {
          EqLocBeforeCurrMBB.erase(reg);
        }
      }
    }
  }
  LLVM_DEBUG(dumpRegTable(EqLocBeforeCurrMBB));
}

void RegisterEquivalence::dumpRegTableAfterMI(MachineInstr *MI) {
  llvm::dbgs() << "Reg Eq Table after: " << *MI;
  auto &Regs = RegInfo[MI];
  for (auto &e : Regs) {
    if (e.first.IsDeref)
      llvm::dbgs() << "deref->";
    llvm::dbgs() << printReg(e.first.RegNum, TRI);
    if (e.first.Offset)
      llvm::dbgs() << "+(" << e.first.Offset << ")";
    llvm::dbgs() << " : { ";
    for (auto &eq : e.second) {
      if (eq.IsDeref)
        llvm::dbgs() << "deref->";
      llvm::dbgs() << printReg(eq.RegNum, TRI);
      if (eq.Offset)
        llvm::dbgs() << "+(" << eq.Offset << ")";
      llvm::dbgs() << " ";
    }
    llvm::dbgs() << "}\n";
  }
  llvm::dbgs() << '\n';
}

std::set<RegisterOffsetPair>
RegisterEquivalence::getEqRegsAfterMI(MachineInstr *MI,
                                      RegisterOffsetPair Reg) {
  if (RegInfo.size() == 0)
    return {};

  if (RegInfo.find(MI) == RegInfo.end())
    return {};

  auto &Regs = RegInfo[MI];
  if (Regs.find(Reg) == Regs.end())
    return {};
  return Regs[Reg];
}

void RegisterEquivalence::dumpRegTable(RegisterEqSet &Regs) {
  llvm::dbgs() << "Reg Eq Table:\n";
  for (auto &e : Regs) {
    if (e.first.IsDeref)
      llvm::dbgs() << "deref->";
    llvm::dbgs() << printReg(e.first.RegNum, TRI);
    if (e.first.Offset)
      llvm::dbgs() << "+(" << e.first.Offset << ")";
    llvm::dbgs() << " : { ";
    for (auto &eq : e.second) {
      if (eq.IsDeref)
        llvm::dbgs() << "deref->";
      llvm::dbgs() << printReg(eq.RegNum, TRI);
      if (eq.Offset)
        llvm::dbgs() << "+(" << eq.Offset << ")";
      llvm::dbgs() << " ";
    }
    llvm::dbgs() << "}\n";
  }
  llvm::dbgs() << '\n';
}

void RegisterEquivalence::invalidateRegEq(MachineInstr &MI,
                                          RegisterOffsetPair Reg) {
  // Remove this reg from all other eq sets.
  auto &Regs = RegInfo[&MI];
  for (auto &eqs : Regs) {
    // Skip itself.
    if (eqs.first == Reg)
      continue;

    eqs.second.erase(Reg);
  }

  RegInfo[&MI][Reg].clear();
  // Insert identity -- reg is eq to itself only.
  RegInfo[&MI][Reg].insert(Reg);
}

void RegisterEquivalence::invalidateAllRegUses(MachineInstr &MI,
                                               RegisterOffsetPair Reg) {
  const MachineFunction *MF = MI.getMF();
  auto TRI = MF->getSubtarget().getRegisterInfo();
  // Firstly, invalidate all equivalences of the Reg.
  invalidateRegEq(MI, Reg);
  if (Reg.IsDeref)
    return;
  auto &Regs = RegInfo[&MI];
  // Then, if the Reg is simple register (ex. $eax):
  // - Invalidate Reg uses as a base register (deref->($eax)+(Offset)).
  // - Invalidate Regs sub/super registers uses as simple registers. (ex. $rax)
  // - Invalidate Regs sub/super registers as base registers. (ex.
  // deref->($rax)+(Offset))
  for (auto &eqs : Regs) {
    if (eqs.first.RegNum && TRI->regsOverlap(eqs.first.RegNum, Reg.RegNum))
      invalidateRegEq(MI, eqs.first);
  }
}

void RegisterEquivalence::setRegEq(MachineInstr &MI, RegisterOffsetPair Src,
                                   RegisterOffsetPair Dest) {
  if (RegInfo[&MI][Dest].find(Src) != RegInfo[&MI][Dest].end())
    return;
  // Set equivalence between Src and Dest.
  RegInfo[&MI][Src].insert(Dest);
  RegInfo[&MI][Dest].insert(Src);
  // Set Src identity equivalence.
  RegInfo[&MI][Src].insert(Src);

  // Set transitive equivalence between Dest and locations equivalent to Src.
  for (auto LL : RegInfo[&MI][Src]) {
    if (LL == Dest || LL == Src)
      continue;
    setRegEq(MI, LL, Dest);
  }
}

bool RegisterEquivalence::applyRegisterCopy(MachineInstr &MI) {
  auto DestSrc = TII->isCopyInstr(MI);
  if (!DestSrc)
    return false;

  const MachineOperand *DestRegOp = DestSrc->Destination;
  const MachineOperand *SrcRegOp = DestSrc->Source;

  Register SrcReg = SrcRegOp->getReg();
  Register DestReg = DestRegOp->getReg();

  // Ignore identity copies. Yep, these make it as far as LiveDebugValues.
  if (SrcReg == DestReg)
    return false;

  RegisterOffsetPair Src{SrcReg};
  RegisterOffsetPair Dest{DestReg};

  // First invalidate dest reg, since it is being rewritten.
  invalidateAllRegUses(MI, Dest);

  // Set (transitive) equivalence.
  setRegEq(MI, Src, Dest);
  return true;
}

bool RegisterEquivalence::areAliases(Register Dst, Register Src) {
  std::string DstRegName = TRI->getRegAsmName(Dst).lower();
  std::string SrcRegName = TRI->getRegAsmName(Src).lower();
  auto CATI = getCATargetInfoInstance();
  auto DstRegInfoId = CATI->getID(DstRegName);
  if (!DstRegInfoId) {
  } else {
    auto DstRegsTuple = CATI->getRegMap(*DstRegInfoId);
    if (std::get<0>(DstRegsTuple) != DstRegName &&
        std::get<0>(DstRegsTuple) == SrcRegName) {
      return true;
    }
    if (std::get<1>(DstRegsTuple) != DstRegName &&
        std::get<1>(DstRegsTuple) == SrcRegName) {
      return true;
    }
    if (std::get<2>(DstRegsTuple) != DstRegName &&
        std::get<2>(DstRegsTuple) == SrcRegName) {
      return true;
    }
    if (std::get<3>(DstRegsTuple) != DstRegName &&
        std::get<3>(DstRegsTuple) == SrcRegName) {
      return true;
    }
  }
  return false;
}

bool RegisterEquivalence::applyLoad(MachineInstr &MI) {
  if (!TII->isLoad(MI))
    return false;

  auto srcDest = TII->getDestAndSrc(MI);
  if (!srcDest)
    return false;

  auto SrcReg = srcDest->Source->getReg();
  auto DestReg = srcDest->Destination->getReg();

  int64_t SrcOffset = 0;

  // Take the offset into account.
  if (srcDest->SrcOffset)
    SrcOffset = *srcDest->SrcOffset;

  // Transform deref->$rip+(off) to deref->$noreg+(rip+off).
  auto CATI = getCATargetInfoInstance();
  std::string RegName = TRI->getRegAsmName(SrcReg).lower();
  if (CATI->isPCRegister(RegName) && CATI->getInstAddr(&MI)) {
    SrcReg = 0;
    SrcOffset += *CATI->getInstAddr(&MI) + *CATI->getInstSize(&MI);
  }

  RegisterOffsetPair Src{SrcReg, SrcOffset};
  Src.IsDeref = true;
  RegisterOffsetPair Dest{DestReg};

  // First invalidate dest reg, since it is being rewritten.
  invalidateAllRegUses(MI, Dest);

  // If SrcReg is redefined (same as DestReg), set only identity equivalence.
  if (Src.RegNum == Dest.RegNum || areAlias(DestReg, SrcReg)) {
    if (RegInfo[&MI][Dest].find(Src) == RegInfo[&MI][Dest].end())
      RegInfo[&MI][Src].insert(Src);
    return true;
  }

  // Set (transitive) equivalence.
  setRegEq(MI, Src, Dest);
  // dumpRegTableAfterMI(&MI);

  return true;
}

bool RegisterEquivalence::applyStore(MachineInstr &MI) {
  if (!TII->isStore(MI))
    return false;

  auto srcDest = TII->getDestAndSrc(MI);
  if (!srcDest)
    return false;

  auto DestReg = srcDest->Destination->getReg();
  int64_t DstOffset = 0;

  // Take the offset into account.
  if (srcDest->DestOffset)
    DstOffset = *srcDest->DestOffset;

  // Transform deref->$rip+(off) to deref->$noreg+(rip+off).
  auto CATI = getCATargetInfoInstance();
  std::string RegName = TRI->getRegAsmName(DestReg).lower();
  if (CATI->isPCRegister(RegName) && CATI->getInstAddr(&MI)) {
    DestReg = 0;
    DstOffset += *CATI->getInstAddr(&MI) + *CATI->getInstSize(&MI);
  }

  RegisterOffsetPair Dest{DestReg, DstOffset};
  Dest.IsDeref = true;

  // We are storing a constant.
  if (!srcDest->Source->isReg()) {
    invalidateAllRegUses(MI, Dest);
    return true;
  }

  auto SrcReg = srcDest->Source->getReg();
  RegisterOffsetPair Src{SrcReg};

  // First invalidate dest reg, since it is being rewritten.
  invalidateAllRegUses(MI, Dest);

  // Set (transitive) equivalence.
  setRegEq(MI, Src, Dest);

  return true;
}

bool RegisterEquivalence::applyCall(MachineInstr &MI) {
  // TODO: Implement this by invalidating registers
  // that will be clobbered by the call.
  // From Retracer: Our static forward analysis is
  // an intra-procedural analysis. We
  // do not analyze callee functions in this analysis.
  // Instead, given a call instruction, we invalidate
  // value relations for volatile registers which
  // can be modified by the callee based on the calling
  // convention [44] as well as memory locations. We also update
  // the stack pointer if the callee is responsible for
  // cleaning up the stack under the function’s calling convention.
  return false;
}

bool RegisterEquivalence::applyRegDef(MachineInstr &MI) {
  for (MachineOperand &MO : MI.operands()) {
    if (MO.isReg() && MO.isDef()) {
      RegisterOffsetPair RegDef{MO.getReg()};
      invalidateAllRegUses(MI, RegDef);
    }
  }
  return true;
}

void RegisterEquivalence::processMI(MachineInstr &MI) {
  if (applyRegisterCopy(MI))
    return;
  if (applyLoad(MI))
    return;
  if (applyStore(MI))
    return;
  if (applyCall(MI))
    return;
  if (applyRegDef(MI))
    return;
}

void RegisterEquivalence::analyzeMachineBasicBlock(
    RegisterEqSet &EqLocBeforeCurrMBB, MachineBasicBlock *MBB) {
  // At the beginning, the previous register equivalence set equals the set of
  // locations that are equivalent before an execution of a basic block.
  RegisterEqSet PrevRegSet = EqLocBeforeCurrMBB;

  // Analyze the instructions of the basic block and update an equivalent
  // locations set.
  for (auto &MI : *MBB) {
    // A register equivalence set before executing a current instruction equals
    // previously calculated register equivalence set.
    RegInfo[&MI] = PrevRegSet;

    // Process different types of MIs.
    processMI(MI);

    // Handle instruction impact onto register equivalence table.
    PrevRegSet = RegInfo[&MI];
    LLVM_DEBUG(dumpRegTableAfterMI(&MI));
  }

  // The set of locations that are equivalent after the execution of the basic
  // block equals a lastly calculated register equivalence set.
  EqLocAfterMBB[MBB->getNumber()] = PrevRegSet;

  auto &EqLocAfterCurrMBB = EqLocAfterMBB[MBB->getNumber()];

  // Identities are redundant in a sense of necessary information for equivalent
  // locations, so they and empty sets are discarded.
  for (auto &regs : make_early_inc_range(EqLocAfterCurrMBB)) {
    RegisterOffsetPair reg{regs.first.RegNum, regs.first.Offset,
                           regs.first.IsDeref};
    EqLocAfterCurrMBB[reg].erase(reg);
    if (EqLocAfterCurrMBB[reg].size() == 0) {
      EqLocAfterCurrMBB.erase(reg);
    }
  }
  LLVM_DEBUG(dumpRegTable(EqLocAfterCurrMBB));
}

void RegisterEquivalence::registerEqDFAnalysis(MachineFunction &MF) {
  // A queue that determines a basic blocks processing order during the
  // equivalent locations analysis.
  std::deque<MachineBasicBlock *> QueueMbb;

  // If a machine function contains at least one basic block, put the entry
  // block into the queue.
  if (MF.begin() != MF.end()) {
    QueueMbb.push_back(&*MF.begin());
  }

  // While the queue is not empty, process a basic block from the beginning of
  // the queue.
  while (!QueueMbb.empty()) {
    auto *MBB = QueueMbb.front();
    QueueMbb.pop_front();

    // An indicator whether the basic block was analyzed.
    bool BlockAnalyzed =
        EqLocAfterMBB.find(MBB->getNumber()) != EqLocAfterMBB.end();

    // An old set of equivalent locations after the last instruction of the
    // basic block.
    auto OldEqLocAfterCurrMBB = EqLocAfterMBB[MBB->getNumber()];

    // Merge locations that are equivalent after an execution of predecessors in
    // order to get locations that are equivalent before an execution of the
    // basic block.
    RegisterEqSet EqLocBeforeCurrMBB;
    join(*MBB, EqLocBeforeCurrMBB);
    auto OldEqLocBeforeCurrMBB = EqLocBeforeMBB[MBB->getNumber()];
    EqLocBeforeMBB[MBB->getNumber()] = EqLocBeforeCurrMBB;

    // There is no need to analyze the block if its set of locations that are
    // equivalent before an execution of the basic block didn't change.
    if (!BlockAnalyzed || EqLocBeforeCurrMBB != OldEqLocBeforeCurrMBB) {
      analyzeMachineBasicBlock(EqLocBeforeCurrMBB, MBB);
    }

    // Check whether the successors need to be analyzed.
    for (auto *Successor : MBB->successors()) {
      // If a successor wasn't analyzed or the set of locations that are
      // equivalent after the execution of the current basic block changed, put
      // a successor into the queue if it hasn't been put.
      if (EqLocAfterMBB.find(Successor->getNumber()) == EqLocAfterMBB.end() ||
          !BlockAnalyzed ||
          OldEqLocAfterCurrMBB != EqLocAfterMBB[MBB->getNumber()]) {
        bool Contains = false;
        for (auto QueueIt = QueueMbb.begin(), QueueItEnd = QueueMbb.end();
             QueueIt != QueueItEnd; QueueIt++) {
          if (*QueueIt == Successor) {
            Contains = true;
            break;
          }
        }
        if (!Contains) {
          QueueMbb.push_back(Successor);
        }
      }
    }
  }
}

bool RegisterEquivalence::isEquivalent(MachineInstr &MI,
                                       RegisterOffsetPair Reg1,
                                       RegisterOffsetPair Reg2) {
  if (RegInfo[&MI][Reg1].find(Reg2) == RegInfo[&MI][Reg1].end())
    return false;
  assert(RegInfo[&MI][Reg2].find(Reg1) != RegInfo[&MI][Reg2].end() &&
         "Register Equivalence is symmetric relation");
  // Transitivity should be handled by setRegEq method.
  return true;
}

bool RegisterEquivalence::verifyEquivalenceTransitivity(
    MachineInstr &MI, RegisterOffsetPair Reg1, RegisterOffsetPair Reg2) {
  if (!isEquivalent(MI, Reg1, Reg2))
    return false;

  for (auto T : RegInfo[&MI][Reg2]) {
    if (!isEquivalent(MI, Reg1, T))
      return false;
  }

  return true;
}

bool RegisterEquivalence::verifyOverlapsInvalidation(MachineInstr &MI,
                                                     unsigned RegNum) {
  auto &Regs = RegInfo[&MI];
  for (auto &eqs : Regs) {
    const MachineFunction *MF = MI.getMF();
    auto TRI = MF->getSubtarget().getRegisterInfo();
    if (eqs.first.RegNum && TRI->regsOverlap(eqs.first.RegNum, RegNum))
      if (eqs.second.size() > 1)
        return false;
  }
  return true;
}

bool RegisterEquivalence::run(MachineFunction &MF) {
  LLVM_DEBUG(llvm::dbgs() << "*** Register Equivalence Analysis ("
                          << MF.getName() << ")***\n";);

  // 1. Perform data flow analysis - join() (or the merge step).
  // 2. Populate the eq table for the basic block for each program point.
  registerEqDFAnalysis(MF);

  LLVM_DEBUG(llvm::dbgs() << "\n\n";);
  return true;
}
