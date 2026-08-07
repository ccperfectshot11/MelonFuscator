using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine;

/// <summary>
/// A sound abstract interpreter that computes the EXACT type of every value on the evaluation
/// stack at the entry of each instruction. Used by MutationProtection (to only rewrite int32
/// arithmetic) and FlattenProtection (to spill live stack values into correctly-typed locals at
/// block boundaries).
///
/// It is a real fixpoint over the control-flow graph. Unknown/ambiguous producers yield null
/// and merges of differing types collapse to null, so a non-null result is always the true type.
/// When anything cannot be modelled safely the whole method returns null and callers do nothing.
/// </summary>
internal static class StackTyper
{
    /// <summary>Entry stack (bottom-to-top) of exact types per instruction, or null to bail.</summary>
    public static IReadOnlyList<TypeSignature?>?[]? Compute(MethodDefinition method) => Compute(method, out _);

    /// <summary>Same, reporting the reason it bailed (for diagnostics).</summary>
    public static IReadOnlyList<TypeSignature?>?[]? Compute(MethodDefinition method, out string bail)
    {
        bail = "ok";
        var body = method.CilMethodBody;
        if (body == null) { bail = "no-body"; return null; }
        var instrs = body.Instructions;
        instrs.CalculateOffsets();
        int n = instrs.Count;
        if (n == 0) { bail = "empty"; return null; }
        var module = method.DeclaringType?.DeclaringModule;
        if (module == null) { bail = "no-module"; return null; }

        var offsetToIndex = new Dictionary<int, int>(n);
        for (int i = 0; i < n; i++) offsetToIndex[instrs[i].Offset] = i;

        var cmp = new SignatureComparer();
        var entry = new List<TypeSignature?>?[n];
        var work = new Queue<int>();

        entry[0] = new List<TypeSignature?>();
        work.Enqueue(0);

        foreach (var eh in body.ExceptionHandlers)
        {
            int h = IndexOf(eh.HandlerStart, offsetToIndex);
            if (h >= 0)
            {
                // catch/filter handler: exception on the stack; finally/fault: empty stack.
                var init = eh.HandlerType is CilExceptionHandlerType.Finally or CilExceptionHandlerType.Fault
                    ? new List<TypeSignature?>()
                    : new List<TypeSignature?> { Sig(eh.ExceptionType, module) ?? module.CorLibTypeFactory.Object };
                Merge(entry, h, init, work, cmp);
            }
            if (eh.HandlerType == CilExceptionHandlerType.Filter)
            {
                int fs = IndexOf(eh.FilterStart, offsetToIndex);
                if (fs >= 0) Merge(entry, fs, new List<TypeSignature?> { module.CorLibTypeFactory.Object }, work, cmp);
            }
        }

        int guard = 0, limit = n * 8 + 1000;
        while (work.Count > 0)
        {
            if (++guard > limit) { bail = "guard-limit"; return null; }
            int i = work.Dequeue();
            var cur = entry[i];
            if (cur == null) continue;

            var stack = new List<TypeSignature?>(cur);
            var ins = instrs[i];
            if (!Simulate(ins, stack, method, module)) { bail = "sim:" + ins.OpCode.Code; return null; }

            if (HasFallThrough(ins.OpCode.Code) && i + 1 < n)
                Merge(entry, i + 1, stack, work, cmp);

            if (ins.Operand is ICilLabel single)
            {
                int t = IndexOf(single, offsetToIndex);
                if (t >= 0) Merge(entry, t, stack, work, cmp);
            }
            else if (ins.Operand is IEnumerable<ICilLabel> many)
            {
                foreach (var l in many)
                {
                    int t = IndexOf(l, offsetToIndex);
                    if (t >= 0) Merge(entry, t, stack, work, cmp);
                }
            }
        }

        var result = new IReadOnlyList<TypeSignature?>?[n];
        for (int i = 0; i < n; i++) result[i] = entry[i];
        return result;
    }

    /// <summary>True if a value of this stack type is a 32-bit integer (incl. bool/char/small ints).</summary>
    public static bool IsInt32(TypeSignature? t) => t?.ElementType is
        ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1
        or ElementType.I2 or ElementType.U2 or ElementType.I4 or ElementType.U4;

    /// <summary>
    /// The type of local to spill a stack value of type <paramref name="t"/> into, or null if it
    /// cannot be spilled safely. Small integers collapse to Int32 (their stack representation);
    /// byref/pointer/native-int cannot be spilled.
    /// </summary>
    public static TypeSignature? SpillType(ModuleDefinition m, TypeSignature? t)
    {
        if (t == null) return null;
        return t.ElementType switch
        {
            ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1
                or ElementType.I2 or ElementType.U2 or ElementType.I4 or ElementType.U4 => m.CorLibTypeFactory.Int32,
            ElementType.I8 or ElementType.U8 => m.CorLibTypeFactory.Int64,
            ElementType.R4 => m.CorLibTypeFactory.Single,
            ElementType.R8 => m.CorLibTypeFactory.Double,
            ElementType.I or ElementType.U or ElementType.Ptr or ElementType.ByRef
                or ElementType.TypedByRef or ElementType.FnPtr => null,
            _ => t,   // string / object / class / array / szarray / generic inst / var / mvar / value type
        };
    }

    // Convert a type reference to a signature, resolving value-type-ness when possible. Returns
    // null (treated as "unknown", never spilled) if it cannot be determined safely.
    private static TypeSignature? Sig(ITypeDefOrRef? t, ModuleDefinition module)
    {
        if (t == null) return null;
        try { return t.ToTypeSignature(module.RuntimeContext); }
        catch { return null; }
    }

    private static int IndexOf(ICilLabel? label, Dictionary<int, int> map)
        => label != null && map.TryGetValue(label.Offset, out int idx) ? idx : -1;

    private static void Merge(List<TypeSignature?>?[] entry, int t, List<TypeSignature?> incoming, Queue<int> work, SignatureComparer cmp)
    {
        var existing = entry[t];
        if (existing == null)
        {
            entry[t] = new List<TypeSignature?>(incoming);
            work.Enqueue(t);
            return;
        }
        if (existing.Count != incoming.Count) return;

        bool changed = false;
        for (int k = 0; k < existing.Count; k++)
        {
            var merged = SameType(existing[k], incoming[k], cmp) ? existing[k] : null;
            if (!SameType(merged, existing[k], cmp)) { existing[k] = merged; changed = true; }
        }
        if (changed) work.Enqueue(t);
    }

    private static bool SameType(TypeSignature? a, TypeSignature? b, SignatureComparer cmp)
    {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        return cmp.Equals(a, b);
    }

    private static bool HasFallThrough(CilCode code) => code switch
    {
        CilCode.Br or CilCode.Br_S or CilCode.Leave or CilCode.Leave_S
            or CilCode.Ret or CilCode.Throw or CilCode.Rethrow
            or CilCode.Endfinally or CilCode.Endfilter or CilCode.Jmp => false,
        _ => true,
    };

    private static bool Simulate(CilInstruction ins, List<TypeSignature?> stack, MethodDefinition method, ModuleDefinition module)
    {
        var f = module.CorLibTypeFactory;
        var code = ins.OpCode.Code;

        switch (code)
        {
            case CilCode.Call:
            case CilCode.Callvirt:
            {
                if (ins.Operand is not IMethodDescriptor m) return false;
                var sig = m.Signature ?? (m as MethodSpecification)?.Method?.Signature;
                if (sig == null) return false;
                if (!PopN(stack, sig.GetTotalParameterCount())) return false;
                if (sig.ReturnsValue)
                    stack.Add(m is MethodSpecification ? null : sig.ReturnType);   // generic return: conservative
                return true;
            }
            case CilCode.Newobj:
            {
                if (ins.Operand is not IMethodDescriptor m) return false;
                var sig = m.Signature ?? (m as MethodSpecification)?.Method?.Signature;
                if (sig == null) return false;
                if (!PopN(stack, sig.ParameterTypes.Count)) return false;
                stack.Add(Sig(m.DeclaringType as ITypeDefOrRef, module));
                return true;
            }
            case CilCode.Calli:
            {
                if (ins.Operand is not StandAloneSignature sas || sas.Signature is not MethodSignature sig) return false;
                if (!PopN(stack, sig.GetTotalParameterCount() + 1)) return false;
                if (sig.ReturnsValue) stack.Add(sig.ReturnType);
                return true;
            }
            case CilCode.Ret:
            {
                var ms = method.Signature;
                if (ms != null && ms.ReturnsValue && stack.Count > 0) stack.RemoveAt(stack.Count - 1);
                return true;
            }
        }

        TypeSignature? t0 = stack.Count >= 1 ? stack[^1] : null;
        TypeSignature? t1 = stack.Count >= 2 ? stack[^2] : null;

        switch (code)
        {
            case CilCode.Ldc_I4_M1: case CilCode.Ldc_I4_0: case CilCode.Ldc_I4_1:
            case CilCode.Ldc_I4_2: case CilCode.Ldc_I4_3: case CilCode.Ldc_I4_4:
            case CilCode.Ldc_I4_5: case CilCode.Ldc_I4_6: case CilCode.Ldc_I4_7:
            case CilCode.Ldc_I4_8: case CilCode.Ldc_I4_S: case CilCode.Ldc_I4:
                stack.Add(f.Int32); return true;
            case CilCode.Ldc_I8: stack.Add(f.Int64); return true;
            case CilCode.Ldc_R4: stack.Add(f.Single); return true;
            case CilCode.Ldc_R8: stack.Add(f.Double); return true;
            case CilCode.Ldstr: stack.Add(f.String); return true;
            case CilCode.Ldnull: stack.Add(f.Object); return true;

            case CilCode.Ldarg_0: case CilCode.Ldarg_1: case CilCode.Ldarg_2:
            case CilCode.Ldarg_3: case CilCode.Ldarg: case CilCode.Ldarg_S:
                stack.Add(ins.GetParameter(method.Parameters)?.ParameterType); return true;
            case CilCode.Ldloc_0: case CilCode.Ldloc_1: case CilCode.Ldloc_2:
            case CilCode.Ldloc_3: case CilCode.Ldloc: case CilCode.Ldloc_S:
                stack.Add(ins.GetLocalVariable(method.CilMethodBody!.LocalVariables)?.VariableType); return true;
            case CilCode.Ldfld:
                if (!PopN(stack, 1)) return false;
                stack.Add((ins.Operand as IFieldDescriptor)?.Signature?.FieldType); return true;
            case CilCode.Ldsfld:
                stack.Add((ins.Operand as IFieldDescriptor)?.Signature?.FieldType); return true;

            case CilCode.Conv_I1: case CilCode.Conv_U1: case CilCode.Conv_I2:
            case CilCode.Conv_U2: case CilCode.Conv_I4: case CilCode.Conv_U4:
            case CilCode.Conv_Ovf_I1: case CilCode.Conv_Ovf_U1: case CilCode.Conv_Ovf_I2:
            case CilCode.Conv_Ovf_U2: case CilCode.Conv_Ovf_I4: case CilCode.Conv_Ovf_U4:
            case CilCode.Conv_Ovf_I1_Un: case CilCode.Conv_Ovf_U1_Un: case CilCode.Conv_Ovf_I2_Un:
            case CilCode.Conv_Ovf_U2_Un: case CilCode.Conv_Ovf_I4_Un: case CilCode.Conv_Ovf_U4_Un:
                if (!PopN(stack, 1)) return false; stack.Add(f.Int32); return true;
            case CilCode.Conv_I8: case CilCode.Conv_U8:
            case CilCode.Conv_Ovf_I8: case CilCode.Conv_Ovf_U8:
            case CilCode.Conv_Ovf_I8_Un: case CilCode.Conv_Ovf_U8_Un:
                if (!PopN(stack, 1)) return false; stack.Add(f.Int64); return true;
            case CilCode.Conv_R4:
                if (!PopN(stack, 1)) return false; stack.Add(f.Single); return true;
            case CilCode.Conv_R8: case CilCode.Conv_R_Un:
                if (!PopN(stack, 1)) return false; stack.Add(f.Double); return true;
            case CilCode.Conv_I: case CilCode.Conv_U:
            case CilCode.Conv_Ovf_I: case CilCode.Conv_Ovf_U:
            case CilCode.Conv_Ovf_I_Un: case CilCode.Conv_Ovf_U_Un:
                if (!PopN(stack, 1)) return false; stack.Add(f.IntPtr); return true;

            case CilCode.Add: case CilCode.Sub: case CilCode.Mul:
            case CilCode.Div: case CilCode.Div_Un: case CilCode.Rem: case CilCode.Rem_Un:
            case CilCode.And: case CilCode.Or: case CilCode.Xor:
            case CilCode.Add_Ovf: case CilCode.Add_Ovf_Un:
            case CilCode.Sub_Ovf: case CilCode.Sub_Ovf_Un:
            case CilCode.Mul_Ovf: case CilCode.Mul_Ovf_Un:
                if (!PopN(stack, 2)) return false; stack.Add(BinaryResult(f, t1, t0)); return true;

            case CilCode.Shl: case CilCode.Shr: case CilCode.Shr_Un:
                if (!PopN(stack, 2)) return false;
                stack.Add(IsInt32(t1) ? f.Int32 : t1?.ElementType is ElementType.I8 or ElementType.U8 ? f.Int64 : null);
                return true;

            case CilCode.Neg: case CilCode.Not:
                if (!PopN(stack, 1)) return false; stack.Add(t0); return true;

            case CilCode.Ceq: case CilCode.Cgt: case CilCode.Cgt_Un:
            case CilCode.Clt: case CilCode.Clt_Un:
                if (!PopN(stack, 2)) return false; stack.Add(f.Int32); return true;

            case CilCode.Ldelem_I1: case CilCode.Ldelem_U1: case CilCode.Ldelem_I2:
            case CilCode.Ldelem_U2: case CilCode.Ldelem_I4: case CilCode.Ldelem_U4:
                if (!PopN(stack, 2)) return false; stack.Add(f.Int32); return true;
            case CilCode.Ldelem_I8:
                if (!PopN(stack, 2)) return false; stack.Add(f.Int64); return true;
            case CilCode.Ldelem_R4:
                if (!PopN(stack, 2)) return false; stack.Add(f.Single); return true;
            case CilCode.Ldelem_R8:
                if (!PopN(stack, 2)) return false; stack.Add(f.Double); return true;
            case CilCode.Ldelem:
                if (!PopN(stack, 2)) return false; stack.Add(Sig(ins.Operand as ITypeDefOrRef, module)); return true;
            case CilCode.Ldelem_Ref: case CilCode.Ldelem_I:
                if (!PopN(stack, 2)) return false; stack.Add(null); return true;

            case CilCode.Ldind_I1: case CilCode.Ldind_U1: case CilCode.Ldind_I2:
            case CilCode.Ldind_U2: case CilCode.Ldind_I4: case CilCode.Ldind_U4:
                if (!PopN(stack, 1)) return false; stack.Add(f.Int32); return true;
            case CilCode.Ldind_I8:
                if (!PopN(stack, 1)) return false; stack.Add(f.Int64); return true;
            case CilCode.Ldind_R4:
                if (!PopN(stack, 1)) return false; stack.Add(f.Single); return true;
            case CilCode.Ldind_R8:
                if (!PopN(stack, 1)) return false; stack.Add(f.Double); return true;
            case CilCode.Ldind_I: case CilCode.Ldind_Ref:
                if (!PopN(stack, 1)) return false; stack.Add(null); return true;

            case CilCode.Castclass: case CilCode.Isinst:
                if (!PopN(stack, 1)) return false; stack.Add(Sig(ins.Operand as ITypeDefOrRef, module)); return true;
            case CilCode.Box:
                if (!PopN(stack, 1)) return false; stack.Add(f.Object); return true;
            case CilCode.Unbox_Any:
                if (!PopN(stack, 1)) return false; stack.Add(Sig(ins.Operand as ITypeDefOrRef, module)); return true;

            case CilCode.Dup:
                stack.Add(t0); return true;

            case CilCode.Sizeof:
                stack.Add(f.Int32); return true;
        }

        int genericPop = PopCount(ins.OpCode.StackBehaviourPop, stack.Count);
        if (genericPop < 0) return false;
        if (!PopN(stack, genericPop)) return false;
        int genericPush = PushCount(ins.OpCode.StackBehaviourPush);
        for (int k = 0; k < genericPush; k++) stack.Add(null);
        return true;
    }

    private static TypeSignature? BinaryResult(CorLibTypeFactory f, TypeSignature? a, TypeSignature? b)
    {
        if (IsInt32(a) && IsInt32(b)) return f.Int32;
        var ea = a?.ElementType; var eb = b?.ElementType;
        if (ea is ElementType.I8 or ElementType.U8 && eb is ElementType.I8 or ElementType.U8) return f.Int64;
        if (ea == ElementType.R4 && eb == ElementType.R4) return f.Single;
        if (ea == ElementType.R8 && eb == ElementType.R8) return f.Double;
        return null;
    }

    private static bool PopN(List<TypeSignature?> stack, int count)
    {
        if (count < 0 || count > stack.Count) return false;
        stack.RemoveRange(stack.Count - count, count);
        return true;
    }

    private static int PopCount(CilStackBehaviour pop, int stackDepth) => pop switch
    {
        CilStackBehaviour.Pop0 => 0,
        CilStackBehaviour.Pop1 or CilStackBehaviour.PopI or CilStackBehaviour.PopRef => 1,
        CilStackBehaviour.Pop1_Pop1 or CilStackBehaviour.PopI_Pop1 or CilStackBehaviour.PopI_PopI
            or CilStackBehaviour.PopI_PopI8 or CilStackBehaviour.PopI_PopR4 or CilStackBehaviour.PopI_PopR8
            or CilStackBehaviour.PopRef_PopI or CilStackBehaviour.PopRef_Pop1 => 2,
        CilStackBehaviour.PopI_PopI_PopI or CilStackBehaviour.PopRef_PopI_PopI
            or CilStackBehaviour.PopRef_PopI_PopI8 or CilStackBehaviour.PopRef_PopI_PopR4
            or CilStackBehaviour.PopRef_PopI_PopR8 or CilStackBehaviour.PopRef_PopI_PopRef
            or CilStackBehaviour.PopRef_PopI_Pop1 => 3,
        CilStackBehaviour.PopAll => stackDepth,
        _ => -1,
    };

    private static int PushCount(CilStackBehaviour push) => push switch
    {
        CilStackBehaviour.Push0 => 0,
        CilStackBehaviour.Push1 or CilStackBehaviour.PushI or CilStackBehaviour.PushI8
            or CilStackBehaviour.PushR4 or CilStackBehaviour.PushR8 or CilStackBehaviour.PushRef => 1,
        CilStackBehaviour.Push1_Push1 => 2,
        _ => 0,
    };
}
