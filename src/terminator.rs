use crate::debugloc::{DebugLoc, HasDebugLoc};
use crate::function::{CallingConvention, FunctionAttribute, ParameterAttribute};
use crate::instruction::{HasResult, InlineAssembly};
use crate::types::{Typed, Types};
use crate::{Constant, ConstantRef, Name, Operand, Type, TypeRef};
use either::Either;
use std::convert::TryFrom;

/// Terminator instructions end a basic block.
/// See [LLVM 10 docs on Terminator Instructions](https://releases.llvm.org/10.0.0/docs/LangRef.html#terminator-instructions)
#[derive(PartialEq, Clone, Debug)]
pub enum Terminator {
    Ret(Ret),
    Br(Br),
    CondBr(CondBr),
    Switch(Switch),
    IndirectBr(IndirectBr),
    Invoke(Invoke),
    Resume(Resume),
    Unreachable(Unreachable),
    CleanupRet(CleanupRet),
    CatchRet(CatchRet),
    CatchSwitch(CatchSwitch),
    CallBr(CallBr),
}

/// The [`Type`](../enum.Type.html) of a `Terminator` is its result type.
/// For most terminators, this is `VoidType`.
/// For instance, a [`Ret`](struct.Ret.html) instruction has void type even if
/// the function returns a non-void value; we do not store the result of a `Ret`
/// instruction using something like `%3 = ret i32 %2`.
/// See [LLVM 10 docs on Terminator Instructions](https://releases.llvm.org/10.0.0/docs/LangRef.html#terminator-instructions)
impl Typed for Terminator {
    fn get_type(&self, types: &Types) -> TypeRef {
        match self {
            Terminator::Ret(t) => types.type_of(t),
            Terminator::Br(t) => types.type_of(t),
            Terminator::CondBr(t) => types.type_of(t),
            Terminator::Switch(t) => types.type_of(t),
            Terminator::IndirectBr(t) => types.type_of(t),
            Terminator::Invoke(t) => types.type_of(t),
            Terminator::Resume(t) => types.type_of(t),
            Terminator::Unreachable(t) => types.type_of(t),
            Terminator::CleanupRet(t) => types.type_of(t),
            Terminator::CatchRet(t) => types.type_of(t),
            Terminator::CatchSwitch(t) => types.type_of(t),
            Terminator::CallBr(t) => types.type_of(t),
        }
    }
}

impl HasDebugLoc for Terminator {
    fn get_debug_loc(&self) -> &Option<DebugLoc> {
        match self {
            Terminator::Ret(t) => t.get_debug_loc(),
            Terminator::Br(t) => t.get_debug_loc(),
            Terminator::CondBr(t) => t.get_debug_loc(),
            Terminator::Switch(t) => t.get_debug_loc(),
            Terminator::IndirectBr(t) => t.get_debug_loc(),
            Terminator::Invoke(t) => t.get_debug_loc(),
            Terminator::Resume(t) => t.get_debug_loc(),
            Terminator::Unreachable(t) => t.get_debug_loc(),
            Terminator::CleanupRet(t) => t.get_debug_loc(),
            Terminator::CatchRet(t) => t.get_debug_loc(),
            Terminator::CatchSwitch(t) => t.get_debug_loc(),
            Terminator::CallBr(t) => t.get_debug_loc(),
        }
    }
}

/* --TODO not yet implemented: metadata
impl Terminator {
    pub fn get_metadata(&self) -> &InstructionMetadata {
        match self {
            Terminator::Ret(t) => &t.metadata,
            Terminator::Br(t) => &t.metadata,
            Terminator::CondBr(t) => &t.metadata,
            Terminator::Switch(t) => &t.metadata,
            Terminator::IndirectBr(t) => &t.metadata,
            Terminator::Invoke(t) => &t.metadata,
            Terminator::Resume(t) => &t.metadata,
            Terminator::Unreachable(t) => &t.metadata,
            Terminator::CleanupRet(t) => &t.metadata,
            Terminator::CatchRet(t) => &t.metadata,
            Terminator::CatchSwitch(t) => &t.metadata,
            Terminator::CallBr(t) => &t.metadata,
        }
    }
}
*/

macro_rules! impl_term {
    ($term:ty, $id:ident) => {
        impl From<$term> for Terminator {
            fn from(term: $term) -> Terminator {
                Terminator::$id(term)
            }
        }

        impl TryFrom<Terminator> for $term {
            type Error = &'static str;
            fn try_from(term: Terminator) -> Result<Self, Self::Error> {
                match term {
                    Terminator::$id(term) => Ok(term),
                    _ => Err("Terminator is not of requested type"),
                }
            }
        }

        impl HasDebugLoc for $term {
            fn get_debug_loc(&self) -> &Option<DebugLoc> {
                &self.debugloc
            }
        }

        /* --TODO not yet implemented: metadata
        impl HasMetadata for $term {
            fn get_metadata(&self) -> &InstructionMetadata {
                &self.metadata
            }
        }
        */
    };
}

macro_rules! impl_hasresult {
    ($term:ty) => {
        impl HasResult for $term {
            fn get_result(&self) -> &Name {
                &self.result
            }
        }
    };
}

macro_rules! void_typed {
    ($term:ty) => {
        impl Typed for $term {
            fn get_type(&self, types: &Types) -> TypeRef {
                types.void()
            }
        }
    };
}

/// See [LLVM 10 docs on the 'ret' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#ret-instruction)
#[derive(PartialEq, Clone, Debug)]
pub struct Ret {
    /// The value being returned, or `None` if returning void.
    pub return_operand: Option<Operand>,
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(Ret, Ret);
void_typed!(Ret); // technically the instruction has void type, even though the function may not

/// See [LLVM 10 docs on the 'br' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#br-instruction).
/// The LLVM 'br' instruction has both conditional and unconditional variants, which we separate -- this is
/// the unconditional variant, while the conditional variant is [`CondBr`](struct.CondBr.html).
#[derive(PartialEq, Clone, Debug)]
pub struct Br {
    /// The [`Name`](../enum.Name.html) of the [`BasicBlock`](../struct.BasicBlock.html) destination.
    pub dest: Name,
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(Br, Br);
void_typed!(Br);

/// See [LLVM 10 docs on the 'br' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#br-instruction).
/// The LLVM 'br' instruction has both conditional and unconditional variants, which we separate -- this is
/// the conditional variant, while the unconditional variant is [`Br`](struct.Br.html).
#[derive(PartialEq, Clone, Debug)]
pub struct CondBr {
    /// The branch condition.
    pub condition: Operand,
    /// The [`Name`](../enum.Name.html) of the [`BasicBlock`](../struct.BasicBlock.html) destination if the `condition` is true.
    pub true_dest: Name,
    /// The [`Name`](../enum.Name.html) of the [`BasicBlock`](../struct.BasicBlock.html) destination if the `condition` is false.
    pub false_dest: Name,
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(CondBr, CondBr);
void_typed!(CondBr);

/// See [LLVM 10 docs on the 'switch' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#switch-instruction)
#[derive(PartialEq, Clone, Debug)]
pub struct Switch {
    pub operand: Operand,
    pub dests: Vec<(ConstantRef, Name)>,
    pub default_dest: Name,
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(Switch, Switch);
void_typed!(Switch);

/// See [LLVM 10 docs on the 'indirectbr' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#indirectbr-instruction)
#[derive(PartialEq, Clone, Debug)]
pub struct IndirectBr {
    /// Address to jump to (must be derived from a [`Constant::BlockAddress`](../enum.Constant.html))
    pub operand: Operand,
    /// The "full set of possible destinations" which the `IndirectBr` could jump to.
    /// These are [`Name`](../enum.Name.html)s of
    /// [`BasicBlock`](../struct.BasicBlock.html)s in the current function;
    /// `IndirectBr` cannot be used to jump between functions.
    pub possible_dests: Vec<Name>,
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(IndirectBr, IndirectBr);
void_typed!(IndirectBr);

/// See [LLVM 10 docs on the 'invoke' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#invoke-instruction)
#[derive(PartialEq, Clone, Debug)]
pub struct Invoke {
    pub function: Either<InlineAssembly, Operand>,
    pub arguments: Vec<(Operand, Vec<ParameterAttribute>)>,
    pub return_attributes: Vec<ParameterAttribute>,
    pub result: Name, // The name of the variable that will get the result of the call (if the callee returns with 'ret')
    pub return_label: Name, // Should be the name of a basic block. If the callee returns normally (i.e., with 'ret'), control flow resumes here.
    pub exception_label: Name, // Should be the name of a basic block. If the callee returns with 'resume' or another exception-handling mechanism, control flow resumes here.
    pub function_attributes: Vec<FunctionAttribute>, // llvm-hs has the equivalent of Vec<Either<GroupID, FunctionAttribute>>, but I'm not sure how the GroupID option comes up
    pub calling_convention: CallingConvention,
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(Invoke, Invoke);
impl_hasresult!(Invoke);

impl Typed for Invoke {
    fn get_type(&self, types: &Types) -> TypeRef {
        match types.type_of(&self.function).as_ref() {
            Type::FuncType { result_type, .. } => result_type.clone(),
            ty => panic!(
                "Expected the function argument of an Invoke to have type FuncType; got {:?}",
                ty
            ),
        }
    }
}

/// See [LLVM 10 docs on the 'resume' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#resume-instruction)
#[derive(PartialEq, Clone, Debug)]
pub struct Resume {
    pub operand: Operand,
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(Resume, Resume);
void_typed!(Resume);

/// See [LLVM 10 docs on the 'unreachable' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#unreachable-instruction)
#[derive(PartialEq, Clone, Debug)]
pub struct Unreachable {
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(Unreachable, Unreachable);
void_typed!(Unreachable);

/// See [LLVM 10 docs on the 'cleanupret' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#cleanupret-instruction)
#[derive(PartialEq, Clone, Debug)]
pub struct CleanupRet {
    pub cleanup_pad: Operand,
    /// `None` here indicates 'unwind to caller'
    pub unwind_dest: Option<Name>,
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(CleanupRet, CleanupRet);
void_typed!(CleanupRet);

/// See [LLVM 10 docs on the 'catchret' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#catchret-instruction)
#[derive(PartialEq, Clone, Debug)]
pub struct CatchRet {
    pub catch_pad: Operand,
    pub successor: Name,
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(CatchRet, CatchRet);
void_typed!(CatchRet);

/// See [LLVM 10 docs on the 'catchswitch' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#catchswitch-instruction)
#[derive(PartialEq, Clone, Debug)]
pub struct CatchSwitch {
    pub parent_pad: Operand,
    /// Cannot be empty
    pub catch_handlers: Vec<Name>,
    /// `None` here indicates 'unwind to caller'
    pub default_unwind_dest: Option<Name>,
    pub result: Name,
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(CatchSwitch, CatchSwitch);
impl_hasresult!(CatchSwitch);

impl Typed for CatchSwitch {
    fn get_type(&self, _types: &Types) -> TypeRef {
        unimplemented!("Typed for CatchSwitch")
        // It's clear that there is a result of this instruction, but the documentation doesn't appear to clearly describe what its type is
    }
}

/// See [LLVM 10 docs on the 'callbr' instruction](https://releases.llvm.org/10.0.0/docs/LangRef.html#callbr-instruction)
#[derive(PartialEq, Clone, Debug)]
pub struct CallBr {
    pub function: Either<InlineAssembly, Operand>,
    pub arguments: Vec<(Operand, Vec<ParameterAttribute>)>,
    pub return_attributes: Vec<ParameterAttribute>,
    pub result: Name, // The name of the variable that will get the result of the call (if the callee returns with 'ret')
    pub return_label: Name, // Should be the name of a basic block. If the callee returns normally (i.e., with 'ret'), control flow resumes here.
    /// `other_labels` should be `Vec<Name>`, but it appears there is no way to get this information with the LLVM C API (as opposed to the C++ API)
    pub other_labels: (), //Vec<Name>, // Should be names of basic blocks. The callee may use an inline-asm 'goto' to resume control flow at one of these places.
    pub function_attributes: Vec<FunctionAttribute>,
    pub calling_convention: CallingConvention,
    pub debugloc: Option<DebugLoc>,
    // --TODO not yet implemented-- pub metadata: InstructionMetadata,
}

impl_term!(CallBr, CallBr);
impl_hasresult!(CallBr);

impl Typed for CallBr {
    fn get_type(&self, types: &Types) -> TypeRef {
        match types.type_of(&self.function).as_ref() {
            Type::FuncType { result_type, .. } => result_type.clone(),
            ty => panic!(
                "Expected the function argument of a CallBr to have type FuncType; got {:?}",
                ty
            ),
        }
    }
}

// ********* //
// from_llvm //
// ********* //

use crate::from_llvm::*;
use crate::function::FunctionContext;
use crate::module::FromLLVMContext;
use llvm_sys::LLVMOpcode;

impl Terminator {
    pub(crate) fn from_llvm_ref(
        term: LLVMValueRef,
        ctx: &mut FromLLVMContext,
        func_ctx: &mut FunctionContext,
    ) -> Self {
        debug!("Processing terminator {:?}", unsafe {
            print_to_string(term)
        });
        match unsafe { LLVMGetInstructionOpcode(term) } {
            LLVMOpcode::LLVMRet => {
                Terminator::Ret(Ret::from_llvm_ref(term, ctx, func_ctx))
            },
            LLVMOpcode::LLVMBr => match unsafe { LLVMGetNumOperands(term) } {
                1 => Terminator::Br(Br::from_llvm_ref(term, func_ctx)),
                3 => Terminator::CondBr(CondBr::from_llvm_ref(term, ctx, func_ctx)),
                n => panic!("LLVMBr with {} operands, expected 1 or 3", n),
            },
            LLVMOpcode::LLVMSwitch => {
                Terminator::Switch(Switch::from_llvm_ref(term, ctx, func_ctx))
            },
            LLVMOpcode::LLVMIndirectBr => {
                Terminator::IndirectBr(IndirectBr::from_llvm_ref(term, ctx, func_ctx))
            },
            LLVMOpcode::LLVMInvoke => {
                Terminator::Invoke(Invoke::from_llvm_ref(term, ctx, func_ctx))
            },
            LLVMOpcode::LLVMResume => {
                Terminator::Resume(Resume::from_llvm_ref(term, ctx, func_ctx))
            },
            LLVMOpcode::LLVMUnreachable => {
                Terminator::Unreachable(Unreachable::from_llvm_ref(term))
            },
            LLVMOpcode::LLVMCleanupRet => {
                Terminator::CleanupRet(CleanupRet::from_llvm_ref(term, ctx, func_ctx))
            },
            LLVMOpcode::LLVMCatchRet => {
                Terminator::CatchRet(CatchRet::from_llvm_ref(term, ctx, func_ctx))
            },
            LLVMOpcode::LLVMCatchSwitch => {
                Terminator::CatchSwitch(CatchSwitch::from_llvm_ref(term, ctx, func_ctx))
            },
            LLVMOpcode::LLVMCallBr => {
                Terminator::CallBr(CallBr::from_llvm_ref(term, ctx, func_ctx))
            },
            opcode => panic!(
                "Terminator::from_llvm_ref called with a non-terminator instruction (opcode {:?})",
                opcode
            ),
        }
    }
}

impl Ret {
    pub(crate) fn from_llvm_ref(
        term: LLVMValueRef,
        ctx: &mut FromLLVMContext,
        func_ctx: &mut FunctionContext,
    ) -> Self {
        Self {
            return_operand: match unsafe { LLVMGetNumOperands(term) } {
                0 => None,
                1 => Some(Operand::from_llvm_ref(
                    unsafe { LLVMGetOperand(term, 0) },
                    ctx,
                    func_ctx,
                )),
                n => panic!("Ret instruction with {} operands", n),
            },
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}

impl Br {
    pub(crate) fn from_llvm_ref(term: LLVMValueRef, func_ctx: &mut FunctionContext) -> Self {
        assert_eq!(unsafe { LLVMGetNumOperands(term) }, 1);
        Self {
            dest: func_ctx
                .bb_names
                .get(unsafe { &op_to_bb(LLVMGetOperand(term, 0)) })
                .expect("Failed to find destination bb in map")
                .clone(),
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}

impl CondBr {
    pub(crate) fn from_llvm_ref(
        term: LLVMValueRef,
        ctx: &mut FromLLVMContext,
        func_ctx: &mut FunctionContext,
    ) -> Self {
        assert_eq!(unsafe { LLVMGetNumOperands(term) }, 3);
        Self {
            condition: Operand::from_llvm_ref(unsafe { LLVMGetOperand(term, 0) }, ctx, func_ctx),
            true_dest: func_ctx
                .bb_names
                .get(unsafe { &op_to_bb(LLVMGetOperand(term, 2)) })
                .expect("Failed to find true-destination bb in map")
                .clone(),
            false_dest: func_ctx
                .bb_names
                .get(unsafe { &op_to_bb(LLVMGetOperand(term, 1)) })
                .expect("Failed to find false-destination in bb map")
                .clone(),
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}

impl Switch {
    pub(crate) fn from_llvm_ref(
        term: LLVMValueRef,
        ctx: &mut FromLLVMContext,
        func_ctx: &mut FunctionContext,
    ) -> Self {
        Self {
            operand: Operand::from_llvm_ref(unsafe { LLVMGetOperand(term, 0) }, ctx, func_ctx),
            dests: {
                let num_dests = unsafe { LLVMGetNumSuccessors(term) };
                let dest_bbs = (1 ..= num_dests) // LLVMGetSuccessor(0) apparently gives the default dest
                    .map(|i| {
                        func_ctx
                            .bb_names
                            .get(unsafe { &LLVMGetSuccessor(term, i) })
                            .expect("Failed to find switch destination in map")
                            .clone()
                    });
                let dest_vals = (1 .. num_dests).map(|i| {
                    Constant::from_llvm_ref(unsafe { LLVMGetOperand(term, 2 * i) }, ctx)
                    // 2*i because empirically, operand 1 is the default dest, and operands 3/5/7/etc are the successor blocks
                });
                Iterator::zip(dest_vals, dest_bbs).collect()
            },
            default_dest: func_ctx
                .bb_names
                .get(unsafe { &LLVMGetSwitchDefaultDest(term) })
                .expect("Failed to find switch default destination in map")
                .clone(),
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}

impl IndirectBr {
    pub(crate) fn from_llvm_ref(
        term: LLVMValueRef,
        ctx: &mut FromLLVMContext,
        func_ctx: &mut FunctionContext,
    ) -> Self {
        Self {
            operand: Operand::from_llvm_ref(unsafe { LLVMGetOperand(term, 0) }, ctx, func_ctx),
            possible_dests: {
                let num_dests = unsafe { LLVMGetNumSuccessors(term) };
                (0 .. num_dests)
                    .map(|i| {
                        func_ctx
                            .bb_names
                            .get(unsafe { &LLVMGetSuccessor(term, i) })
                            .expect("Failed to find indirect branch destination in map")
                            .clone()
                    })
                    .collect()
            },
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}

impl Invoke {
    pub(crate) fn from_llvm_ref(
        term: LLVMValueRef,
        ctx: &mut FromLLVMContext,
        func_ctx: &mut FunctionContext,
    ) -> Self {
        use crate::instruction::CallInfo;
        let callinfo = CallInfo::from_llvm_ref(term, ctx, func_ctx);
        Self {
            function: callinfo.function,
            arguments: callinfo.arguments,
            return_attributes: callinfo.return_attributes,
            result: Name::name_or_num(unsafe { get_value_name(term) }, &mut func_ctx.ctr),
            return_label: func_ctx
                .bb_names
                .get(unsafe { &LLVMGetNormalDest(term) })
                .expect("Failed to find invoke return destination in map")
                .clone(),
            exception_label: func_ctx
                .bb_names
                .get(unsafe { &LLVMGetUnwindDest(term) })
                .expect("Failed to find invoke exception destination in map")
                .clone(),
            function_attributes: callinfo.function_attributes,
            calling_convention: callinfo.calling_convention,
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}

impl Resume {
    pub(crate) fn from_llvm_ref(
        term: LLVMValueRef,
        ctx: &mut FromLLVMContext,
        func_ctx: &mut FunctionContext,
    ) -> Self {
        assert_eq!(unsafe { LLVMGetNumOperands(term) }, 1);
        Self {
            operand: Operand::from_llvm_ref(unsafe { LLVMGetOperand(term, 0) }, ctx, func_ctx),
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}

impl Unreachable {
    pub(crate) fn from_llvm_ref(term: LLVMValueRef) -> Self {
        assert_eq!(unsafe { LLVMGetNumOperands(term) }, 0);
        Self {
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}

impl CleanupRet {
    pub(crate) fn from_llvm_ref(
        term: LLVMValueRef,
        ctx: &mut FromLLVMContext,
        func_ctx: &mut FunctionContext,
    ) -> Self {
        assert_eq!(unsafe { LLVMGetNumOperands(term) }, 1);
        Self {
            cleanup_pad: Operand::from_llvm_ref(unsafe { LLVMGetOperand(term, 0) }, ctx, func_ctx),
            unwind_dest: {
                let dest = unsafe { LLVMGetUnwindDest(term) };
                if dest.is_null() {
                    None
                } else {
                    Some(
                        func_ctx
                            .bb_names
                            .get(&dest)
                            .unwrap_or_else(|| {
                                let names: Vec<_> = func_ctx.bb_names.values().collect();
                                panic!(
                                    "Failed to find unwind destination in map; have names {:?}",
                                    names
                                )
                            })
                            .clone(),
                    )
                }
            },
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}

impl CatchRet {
    pub(crate) fn from_llvm_ref(
        term: LLVMValueRef,
        ctx: &mut FromLLVMContext,
        func_ctx: &mut FunctionContext,
    ) -> Self {
        Self {
            catch_pad: Operand::from_llvm_ref(unsafe { LLVMGetOperand(term, 0) }, ctx, func_ctx),
            successor: func_ctx
                .bb_names
                .get(unsafe { &LLVMGetSuccessor(term, 0) })
                .expect("Failed to find CatchRet successor in map")
                .clone(),
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}

impl CatchSwitch {
    pub(crate) fn from_llvm_ref(
        term: LLVMValueRef,
        ctx: &mut FromLLVMContext,
        func_ctx: &mut FunctionContext,
    ) -> Self {
        Self {
            parent_pad: Operand::from_llvm_ref(unsafe { LLVMGetOperand(term, 0) }, ctx, func_ctx),
            catch_handlers: {
                let num_handlers = unsafe { LLVMGetNumHandlers(term) };
                let mut handlers: Vec<LLVMBasicBlockRef> =
                    Vec::with_capacity(num_handlers as usize);
                unsafe {
                    LLVMGetHandlers(term, handlers.as_mut_ptr());
                    handlers.set_len(num_handlers as usize);
                };
                handlers
                    .into_iter()
                    .map(|h| {
                        func_ctx
                            .bb_names
                            .get(&h)
                            .expect("Failed to find catch handler in map")
                            .clone()
                    })
                    .collect()
            },
            default_unwind_dest: {
                let dest = unsafe { LLVMGetUnwindDest(term) };
                if dest.is_null() {
                    None
                } else {
                    Some(func_ctx.bb_names.get(&dest)
                        .unwrap_or_else(|| { let names: Vec<_> = func_ctx.bb_names.values().collect(); panic!("Failed to find CatchSwitch default unwind destination in map; have names {:?}", names) })
                        .clone()
                    )
                }
            },
            result: Name::name_or_num(unsafe { get_value_name(term) }, &mut func_ctx.ctr),
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}

impl CallBr {
    pub(crate) fn from_llvm_ref(
        term: LLVMValueRef,
        ctx: &mut FromLLVMContext,
        func_ctx: &mut FunctionContext,
    ) -> Self {
        use crate::instruction::CallInfo;
        let callinfo = CallInfo::from_llvm_ref(term, ctx, func_ctx);
        Self {
            function: callinfo.function,
            arguments: callinfo.arguments,
            return_attributes: callinfo.return_attributes,
            result: Name::name_or_num(unsafe { get_value_name(term) }, &mut func_ctx.ctr),
            return_label: func_ctx
                .bb_names
                .get(unsafe { &LLVMGetNormalDest(term) })
                .expect("Failed to find invoke return destination in map")
                .clone(),
            other_labels: (),
            function_attributes: callinfo.function_attributes,
            calling_convention: callinfo.calling_convention,
            debugloc: DebugLoc::from_llvm_with_col(term),
            // metadata: InstructionMetadata::from_llvm_inst(term),
        }
    }
}