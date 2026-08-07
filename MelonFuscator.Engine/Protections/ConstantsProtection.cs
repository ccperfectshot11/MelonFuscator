using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Numeric constant encryption (ConfuserEx-style, MelonLoader-safe). Non-trivial int32
/// literals (ldc.i4 / ldc.i4.s, i.e. everything except the tiny macro constants -1..8) are
/// replaced with their encrypted value plus a call to an in-module decoder, so the real
/// numbers never appear in the disassembly. Uses the per-build ByteCipher (portable integer
/// math only).
/// </summary>
public sealed class ConstantsProtection : IProtection
{
    public string Name => "Constant Encryption";
    public bool IsEnabled(ObfuscationOptions o) => o.EncryptConstants;

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var holder = CilHelpers.CreateStaticHolder(module, ctx.Names.Next());
        var decode = EmitDecodeI4(module, holder, ctx.Cipher);

        // Snapshot bodies before adding the decoder so we never rewrite it. Compiler-generated
        // iterator/async state machines are skipped: rewriting their state constants into decode
        // calls corrupts the resume dispatch (InvalidProgramException at runtime).
        var methods = module.GetAllTypes()
            .Where(t => !CilHelpers.IsCompilerStateMachine(t))
            .SelectMany(t => t.Methods)
            .Where(m => m.CilMethodBody != null && m != decode)
            .ToList();

        int count = 0;
        foreach (var method in methods)
        {
            var instrs = method.CilMethodBody!.Instructions;
            for (int i = 0; i < instrs.Count; i++)
            {
                var ins = instrs[i];
                if (!TryGetInt(ins, out int value)) continue;

                ins.OpCode = CilOpCodes.Ldc_I4;
                ins.Operand = ctx.Cipher.EncryptInt32(value);
                instrs.Insert(i + 1, new CilInstruction(CilOpCodes.Call, decode));
                i++;
                count++;
            }
        }

        ctx.Log.Step($"encrypted {count} numeric constant(s)");
    }

    // Only the non-macro forms carry a "real" value worth hiding.
    private static bool TryGetInt(CilInstruction ins, out int value)
    {
        value = 0;
        if (ins.OpCode.Code == CilCode.Ldc_I4 && ins.Operand is int i) { value = i; return true; }
        if (ins.OpCode.Code == CilCode.Ldc_I4_S && ins.Operand is sbyte sb) { value = sb; return true; }
        return false;
    }

    private static MethodDefinition EmitDecodeI4(ModuleDefinition module, TypeDefinition holder, ByteCipher cipher)
    {
        var sig = MethodSignature.CreateStatic(module.CorLibTypeFactory.Int32,
            new TypeSignature[] { module.CorLibTypeFactory.Int32 });
        var m = new MethodDefinition("DecodeI4",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, sig);
        holder.Methods.Add(m);

        var body = new CilMethodBody();
        m.CilMethodBody = body;
        var n = body.Instructions;
        n.Add(new CilInstruction(CilOpCodes.Ldarg_0));
        cipher.EmitDecryptInt32(n);
        n.Add(new CilInstruction(CilOpCodes.Ret));
        body.Instructions.CalculateOffsets();
        return m;
    }
}
