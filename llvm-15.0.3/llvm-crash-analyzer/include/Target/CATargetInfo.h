//==- CATargetInfo.h - Crash Analyzer Target Information ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file describes the target machine interfece to the Crash Analyzer.
//
//===----------------------------------------------------------------------===//

#ifndef CA_TARGET_INFO_
#define CA_TARGET_INFO_

#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/Triple.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Host.h"

#include <tuple>
#include <unordered_map>

using namespace llvm;

// Map register aliases.
using RegAliasTuple =
    std::tuple<std::string, std::string, std::string, std::string>;

// Crash Analyzer Target Information interface.
class CATargetInfo {
protected:
  static const Triple *TT;
  // This will be mapped into register aliases.
  // e.g. rax, eax, ax will hold a same id.
  std::unordered_map<unsigned, RegAliasTuple> RegMap;

  // Save PC value for each instruction.
  std::unordered_map<const MachineInstr *, std::pair<uint64_t, uint64_t>>
      InstAddrs;

  // Singleton class for the CATargetInfo instance.
  template <typename T> class Singleton {
  private:
  public:
    static T *get(void) {
      static T TheInstance;
      return &TheInstance;
    }
  };

public:
  CATargetInfo() {}
  virtual ~CATargetInfo() {
    RegMap.clear();
    InstAddrs.clear();
  }

  // Get register index in the RegMap.
  virtual Optional<unsigned> getID(std::string RegName) const = 0;

  // Get register unsigned (MCRegister) from the RegMap.
  virtual Optional<unsigned> getRegister(std::string RegName,
                                         const MachineInstr *MI) const = 0;

  virtual unsigned getRegSize(std::string RegName) const = 0;

  // Get RegAliasTuple from the RegMap with selected Id.
  RegAliasTuple &getRegMap(unsigned Id) const {
    return const_cast<RegAliasTuple &>(RegMap.at(Id));
  }

  // Get whole RegMap.
  const std::unordered_map<unsigned, RegAliasTuple> &getWholeRegMap() const {
    return RegMap;
  }

  // Get InstAddr from the InstAddrs map for the MI.
  Optional<uint64_t> getInstAddr(const MachineInstr *MI) {
    if (InstAddrs.count(MI) == 0)
      return None;
    return InstAddrs[MI].first;
  }

  // Get InstAddr from the InstAddrs map for the MI.
  Optional<uint64_t> getInstSize(const MachineInstr *MI) {
    if (InstAddrs.count(MI) == 0)
      return None;
    return InstAddrs[MI].second;
  }

  // Set InstAddr in the InstAddrs map for the MI.
  void setInstAddr(const MachineInstr *MI, uint64_t InstAddr,
                   uint64_t InstSize = 0) {
    InstAddrs[MI] = {InstAddr, InstSize};
  }

  // Return true if the register is used for function return value.
  virtual bool isRetValRegister(std::string RegName) const = 0;

  // Return true if the register is Program Counter Register.
  virtual bool isPCRegister(std::string RegName) const = 0;

  // Return name of the Program Counter Register.
  virtual Optional<std::string> getPC() const = 0;

  // Return name of the Base Pointer Register.
  virtual Optional<std::string> getBP() const = 0;

  // Return name of the Stack Pointer Register.
  virtual Optional<std::string> getSP() const = 0;

  // Return true if the register is Stack Pointer Register.
  virtual bool isSPRegister(std::string RegName) const = 0;

  // Return SP adjustment to BP in the callee.
  virtual int64_t getSPAdjust() const = 0;

  // Return true if the register is Base Pointer Register.
  virtual bool isBPRegister(std::string RegName) const = 0;

  // Return true if the register can be used to forward parameters.
  virtual bool isParamFwdRegister(std::string RegName) const = 0;

  // Set target Triple of the CATargetInfo instance.
  static void initializeCATargetInfo(Triple *Triple) {
    if (!TT)
      TT = Triple;
    else
      assert(*TT == *Triple && "Target triple changed!");
  }

  // Get target Triple of the CATargetInfo instance.
  static const Triple *getTargetTriple() { return TT; }
};

class X86CATargetInfo : public CATargetInfo {
public:
  X86CATargetInfo();
  ~X86CATargetInfo() {}

  Optional<unsigned> getID(std::string RegName) const override;

  Optional<unsigned> getRegister(std::string RegName,
                                 const MachineInstr *MI) const override;

  unsigned getRegSize(std::string RegName) const override;

  bool isRetValRegister(std::string RegName) const override;

  bool isPCRegister(std::string RegName) const override;

  Optional<std::string> getPC() const override;

  Optional<std::string> getBP() const override;

  Optional<std::string> getSP() const override;

  bool isSPRegister(std::string RegName) const override;

  // Return SP adjustment to BP in the callee.
  int64_t getSPAdjust() const override;

  bool isBPRegister(std::string RegName) const override;

  bool isParamFwdRegister(std::string RegName) const override;

  // Define static instance getter for each target.
  static X86CATargetInfo *instance() {
    return CATargetInfo::Singleton<X86CATargetInfo>::get();
  }
};

// Get CATargetInfo instance for available target.
inline static CATargetInfo *getCATargetInfoInstance() {
  // If not initialized, use default system target.
  if (!CATargetInfo::getTargetTriple()) {
    std::string TargetTripleString = sys::getDefaultTargetTriple();
    static Triple TargetTriple(Triple::normalize(TargetTripleString));
    CATargetInfo::initializeCATargetInfo(&TargetTriple);
  }
  switch (CATargetInfo::getTargetTriple()->getArch()) {
  case Triple::x86_64:
    return X86CATargetInfo::instance();
  default:
    llvm_unreachable("Target architecture not supported.");
  }
}

// Return true if the target is supported.
inline static bool isCATargetSupported(Triple TargetTriple) {
  switch (TargetTriple.getArch()) {
  case Triple::x86_64:
    return true;
  default:
    return false;
  }
}

#endif