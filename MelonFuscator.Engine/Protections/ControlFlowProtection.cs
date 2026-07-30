using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Control-flow obfuscation via opaque predicates. A static field (value 0) is read at
/// every method entry and used in an always-taken conditional jump to the real body, with
/// a dead junk block in between. A decompiler cannot prove the field's value, so it cannot
/// remove the bogus branch, which makes the reconstructed control flow noisy and wrong.
/// Prepending is exception-handler-safe because handler boundaries reference the original
/// instruction objects, which keep their identity.
/// </summary>
public sealed class ControlFlowProtection : IProtection
{
    public string Name => "Control Flow";
    public bool IsEnabled(ObfuscationOptions o) => o.ControlFlow;

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;

        var holder = CilHelpers.CreateStaticHolder(module, ctx.Names.Next());
        var opaque = new FieldDefinition(ctx.Names.Next(),
            FieldAttributes.Public | FieldAttributes.Static, module.CorLibTypeFactory.Int32);
        holder.Fields.Add(opaque);   // defaults to 0

        var methods = module.GetAllTypes()
            .SelectMany(t => t.Methods)
            .Where(m => m.CilMethodBody is { } b && b.Instructions.Count > 0)
            .ToList();

        int done = 0;
        foreach (var method in methods)
        {
            var instrs = method.CilMethodBody!.Instructions;
            var realFirst = instrs[0];

            var prologue = new List<CilInstruction>
            {
                new CilInstruction(CilOpCodes.Ldsfld, opaque),
                new CilInstruction(CilOpCodes.Brfalse, new CilInstructionLabel(realFirst)),
                new CilInstruction(CilOpCodes.Ldc_I4, ctx.Rng.Next()),
                new CilInstruction(CilOpCodes.Pop),
            };

            for (int j = prologue.Count - 1; j >= 0; j--)
                instrs.Insert(0, prologue[j]);

            instrs.CalculateOffsets();
            done++;
        }

        ctx.Log.Step($"inserted opaque predicates into {done} method(s)");
    }
}
