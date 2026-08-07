using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Data/value encoding. Every eligible 32-bit integer local variable is kept in memory in an
/// encoded form: a per-local random key K is chosen, every store writes <c>value ^ K</c> and
/// every load reads it back and applies <c>^ K</c>. The decoded value only ever exists briefly
/// on the evaluation stack, so a memory dump or a watch on the local shows scrambled data, and
/// a decompiler sees every read/write wrapped in noise.
///
/// XOR is self-inverse and lossless on a full 32-bit slot, so behavior is bit-for-bit identical.
/// For correctness we only touch Int32/UInt32 locals (no truncation), and skip any local whose
/// address is taken (ldloca) or whose store is a branch target (a jump could skip the encode).
/// </summary>
public sealed class DataEncryptionProtection : IProtection
{
    public string Name => "Data Encoding";
    public bool IsEnabled(ObfuscationOptions o) => o.EncodeLocals;

    public void Execute(ObfuscationContext ctx)
    {
        int encodedLocals = 0, touchedMethods = 0;
        foreach (var type in ctx.Module.GetAllTypes())
        {
            // Skip compiler-generated iterator/async state machines: XOR-encoding the locals their
            // MoveNext relies on for resume corrupts the state protocol (InvalidProgramException).
            if (CilHelpers.IsCompilerStateMachine(type)) continue;

            foreach (var method in type.Methods)
            {
                var body = method.CilMethodBody;
                if (body == null || body.LocalVariables.Count == 0) continue;
                if (EncodeMethod(body, ctx, out int count)) { encodedLocals += count; touchedMethods++; }
            }
        }
        ctx.Log.Step($"encoded {encodedLocals} integer local(s) across {touchedMethods} method(s)");
    }

    private static bool EncodeMethod(CilMethodBody body, ObfuscationContext ctx, out int count)
    {
        count = 0;
        var instrs = body.Instructions;
        instrs.CalculateOffsets();

        // Candidate locals: Int32 / UInt32 only (4-byte slots, XOR is lossless).
        var keys = new Dictionary<CilLocalVariable, int>();
        foreach (var lv in body.LocalVariables)
        {
            var et = lv.VariableType?.ElementType;
            if (et is ElementType.I4 or ElementType.U4)
                keys[lv] = ctx.Rng.Next() | 1;   // non-zero key
        }
        if (keys.Count == 0) return false;

        // Disqualify locals whose address is taken - we cannot intercept access through a pointer.
        foreach (var ins in instrs)
        {
            if (ins.OpCode.Code is CilCode.Ldloca or CilCode.Ldloca_S)
            {
                var lv = ins.GetLocalVariable(body.LocalVariables);
                if (lv != null) keys.Remove(lv);
            }
        }

        // Disqualify locals whose store is a branch target: a jump straight to the store would
        // skip the encode and leave a raw value in the slot.
        var targetOffsets = new HashSet<int>();
        foreach (var ins in instrs)
        {
            if (ins.Operand is ICilLabel l) targetOffsets.Add(l.Offset);
            else if (ins.Operand is IEnumerable<ICilLabel> ls)
                foreach (var x in ls) targetOffsets.Add(x.Offset);
        }
        foreach (var ins in instrs)
        {
            if (IsStloc(ins.OpCode.Code) && targetOffsets.Contains(ins.Offset))
            {
                var lv = ins.GetLocalVariable(body.LocalVariables);
                if (lv != null) keys.Remove(lv);
            }
        }

        if (keys.Count == 0) return false;

        // Rebuild the instruction stream, wrapping each load/store of an encoded local. Original
        // instruction objects are preserved, so every branch/handler label stays valid.
        var rebuilt = new List<CilInstruction>(instrs.Count);
        foreach (var ins in instrs)
        {
            var code = ins.OpCode.Code;
            bool isLd = IsLdloc(code), isSt = IsStloc(code);
            // GetLocalVariable throws on non-local opcodes, so only call it for real loads/stores.
            var lv = (isLd || isSt) ? ins.GetLocalVariable(body.LocalVariables) : null;
            if (lv != null && keys.TryGetValue(lv, out int key))
            {
                if (isLd)
                {
                    rebuilt.Add(ins);                                       // load encoded value
                    rebuilt.Add(new CilInstruction(CilOpCodes.Ldc_I4, key));
                    rebuilt.Add(new CilInstruction(CilOpCodes.Xor));        // -> decoded
                    continue;
                }
                // isSt
                rebuilt.Add(new CilInstruction(CilOpCodes.Ldc_I4, key));
                rebuilt.Add(new CilInstruction(CilOpCodes.Xor));            // encode before storing
                rebuilt.Add(ins);
                continue;
            }
            rebuilt.Add(ins);
        }

        instrs.Clear();
        foreach (var ins in rebuilt) instrs.Add(ins);
        instrs.CalculateOffsets();
        count = keys.Count;
        return true;
    }

    private static bool IsLdloc(CilCode c) => c is
        CilCode.Ldloc or CilCode.Ldloc_S or CilCode.Ldloc_0 or CilCode.Ldloc_1
        or CilCode.Ldloc_2 or CilCode.Ldloc_3;

    private static bool IsStloc(CilCode c) => c is
        CilCode.Stloc or CilCode.Stloc_S or CilCode.Stloc_0 or CilCode.Stloc_1
        or CilCode.Stloc_2 or CilCode.Stloc_3;
}
