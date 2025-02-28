//===- TaintAnalysis.h - Catch the source of a crash ----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef TAINTANALYSIS_
#define TAINTANALYSIS_

#include "Decompiler/Decompiler.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include "Analysis/MemoryWrapper.h"

struct Node;
class TaintDataFlowGraph;
class RegisterEquivalence;
class ConcreteReverseExec;

namespace llvm {
namespace crash_analyzer {

enum TaintInfoType { ImmediateVal, RegisterLoc, MemoryLoc };

// Tainted Operands in a Machine Instruction.
// This is a Reg-Offset pair.
// TODO: Take into account:
//   1) Register as offset
//   2) Scaled Index addressing mode
struct TaintInfo {
  const MachineOperand *Op = nullptr;
  MachineOperand *Scale = nullptr;
  MachineOperand *IndexReg = nullptr;

  // For mem operands, we rather choose to taint
  // real/concrete addresses (by calculating base_reg + off).
  Optional<int64_t> Offset;
  uint64_t ConcreteMemoryAddress = 0x0;
  bool IsConcreteMemory = false;
  bool IsTaintMemAddr() const { return IsConcreteMemory; }
  uint64_t GetTaintMemAddr() const { return ConcreteMemoryAddress; }
  std::tuple<unsigned, int, int> getTuple() const;

  int DerefLevel = 0;
  void propagateDerefLevel(const MachineInstr &MI);

  bool IsGlobal = false;
  // Added for differentiating reg + off from memory pointed by (reg)+off
  bool IsDeref = false;

  friend bool operator==(const TaintInfo &T1, const TaintInfo &T2);
  friend bool operator!=(const TaintInfo &T1, const TaintInfo &T2);
  friend bool operator<(const TaintInfo &T1, const TaintInfo &T2);
  friend raw_ostream &operator<<(raw_ostream &os, const TaintInfo &T);
  bool isTargetStartTaint(unsigned CrashOrder) const;
};

class TaintAnalysis {
private:
  StringRef TaintDotFileName;
  StringRef MirDotFileName;
  SmallVector<TaintInfo, 8> TaintList;
  Decompiler *Dec = nullptr;
  MemoryWrapper MemWrapper;

  // We use this flag to avoid decompilation on demand
  // for calls in the case of llvm-crash-analyzer-ta tool.
  bool isCrashAnalyzerTATool = false;

  // Used to indicate that we faced a non inlined frame.
  unsigned analysisStartedAt = 1;
  bool PrintPotentialCrashCauseLocation = false;
  ConcreteReverseExec *CRE = nullptr;
  RegisterEquivalence *REA = nullptr;

  // Used for functions out of the backtrace.
  SmallVector<TaintInfo, 8> TL_Of_Call;

public:
  TaintAnalysis(StringRef TaintDotFileName, StringRef MirDotFileName,
                bool PrintPotentialCrashCauseLocation);
  TaintAnalysis(bool b) : isCrashAnalyzerTATool(b) {}

  bool runOnBlameModule(BlameModule &BM);
  bool runOnBlameMF(BlameModule &BM, const MachineFunction &MF,
                    TaintDataFlowGraph &TaintDFG, bool CalleeNotInBT,
                    unsigned levelOfCalledFn,
                    SmallVector<TaintInfo, 8> *TL_Of_Caller = nullptr,
                    const MachineInstr *CallMI = nullptr);

  void resetTaintList(SmallVectorImpl<TaintInfo> &TL);
  void mergeTaintList(SmallVectorImpl<TaintInfo> &Dest_TL,
                      SmallVectorImpl<TaintInfo> &Src_TL);
  bool handleGlobalVar(TaintInfo &Ti);
  bool propagateTaint(DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL,
                      const MachineInstr &MI, TaintDataFlowGraph &TaintDFG,
                      RegisterEquivalence &REAnalysis,
                      const MachineInstr *CallMI = nullptr);
  void startTaint(DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL,
                  const MachineInstr &MI, TaintDataFlowGraph &TaintDFG,
                  RegisterEquivalence &REAnalysis);
  bool forwardMFAnalysis(BlameModule &BM, const MachineFunction &MF,
                         TaintDataFlowGraph &TaintDFG,
                         unsigned levelOfCalledFn = 0,
                         SmallVector<TaintInfo, 8> *TL_Of_Caller = nullptr,
                         const MachineInstr *CallMI = nullptr);
  bool propagateTaintFwd(DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL,
                         const MachineInstr &MI, TaintDataFlowGraph &TaintDFG,
                         RegisterEquivalence &REAnalysis,
                         const MachineInstr *CallMI = nullptr);
  void addNewTaint(TaintInfo &Ti, SmallVectorImpl<TaintInfo> &TL,
                   const MachineInstr &MI, TaintDataFlowGraph &TaintDFG,
                   std::shared_ptr<Node> crashNode);
  void insertTaint(DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL,
                   const MachineInstr &MI, TaintDataFlowGraph &TaintDFG,
                   RegisterEquivalence &REAnalysis);
  bool continueAnalysis(const MachineInstr &MI, SmallVectorImpl<TaintInfo> &TL,
                        RegisterEquivalence &REAnalysis);
  void removeFromTaintList(TaintInfo &Op, SmallVectorImpl<TaintInfo> &TL);
  bool addToTaintList(TaintInfo &Ti, SmallVectorImpl<TaintInfo> &TL);
  void updateTaintDerefLevel(TaintInfo &Ti, SmallVectorImpl<TaintInfo> &TL,
                             const MachineInstr &MI);
  void printTaintList(SmallVectorImpl<TaintInfo> &TL);
  void printTaintList2(SmallVectorImpl<TaintInfo> &TL);
  void printDestSrcInfo(DestSourcePair &DS, const MachineInstr &MI);
  bool shouldAnalyzeCall(SmallVectorImpl<TaintInfo> &TL);
  bool areParamsTainted(const MachineInstr *CallMI,
                        SmallVectorImpl<TaintInfo> &TL,
                        SmallVectorImpl<TaintInfo> *TL_Of_Caller,
                        TaintDataFlowGraph &TaintDFG,
                        RegisterEquivalence &REAnalysis);
  const MachineInstr *findParamLoadingInstr(TaintInfo &Ti,
                                            const MachineInstr *CallMI);
  void transformBPtoSPTaints(const MachineFunction &MF,
                             TaintDataFlowGraph &TaintDFG,
                             SmallVectorImpl<TaintInfo> &TL);
  void transformSPtoBPTaints(const MachineFunction &MF,
                             TaintDataFlowGraph &TaintDFG,
                             SmallVectorImpl<TaintInfo> &TL);
  bool isStackSlotTainted(const MachineInstr *CallMI,
                          SmallVectorImpl<TaintInfo> &TL,
                          SmallVectorImpl<TaintInfo> *TL_Of_Caller,
                          TaintDataFlowGraph &TaintDFG,
                          RegisterEquivalence *REAnalysis);
  TaintInfo isTainted(TaintInfo &Op, SmallVectorImpl<TaintInfo> &TL,
                      RegisterEquivalence *REAnalysis = nullptr,
                      const MachineInstr *MI = nullptr);
  void calculateMemAddr(TaintInfo &Ti);
  MachineFunction *getCalledMF(const BlameModule &BM, std::string Name);
  bool getIsCrashAnalyzerTATool() const;
  void setDecompiler(Decompiler *D);
  Decompiler *getDecompiler() const;
  void setCRE(ConcreteReverseExec *cre);
  ConcreteReverseExec *getCRE() const;
  void setREAnalysis(RegisterEquivalence *rea);
  RegisterEquivalence *getREAnalysis();
  /// This is a structure that is used as an element of a queue which determines
  /// the order of visiting MachineBasicBlocks during taint analysis.
  /// It contains a MachineBasicBlock which should be visited and its successors
  /// through which it was reached during revese execution of instructions.
  /// In general, a MachineBasicBlock should have a maximum of two successors,
  /// because during decompilation after branch instruction it is created a new
  /// MachineBasicBlock.
  struct TaintAnalysisQueueElem {
    MachineBasicBlock *MBB;
    SmallVector<MachineBasicBlock *, 8> Successors;
    TaintAnalysisQueueElem(MachineBasicBlock *MBB) : MBB(MBB) {}
  };
  /// @brief Merges register values from successors. If two registers with the
  /// same name have different values in two successors, a value of that
  /// register is invalidated.
  /// @param RegVals maps a block into the register values information
  /// @param QueueElem contains a block that should be processed and its
  /// successors thorugh which it was reached
  void mergeRegVals(DenseMap<const MachineBasicBlock *,
                             MachineFunction::RegisterCrashInfo> &RegVals,
                    TaintAnalysisQueueElem &QueueElem);
};

} // namespace crash_analyzer
} // namespace llvm

#endif
