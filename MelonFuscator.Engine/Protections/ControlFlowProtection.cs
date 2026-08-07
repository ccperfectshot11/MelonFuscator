using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Control-flow obfuscation via strong opaque predicates. Several static int fields are seeded
/// at load time from a runtime source (Environment.TickCount xored with a per-build constant),
/// so a decompiler cannot constant-fold their value. Each method entry is prefixed with a
/// predicate that is mathematically TRUE for every possible int (e.g. <c>(x | 1) != 0</c>, or
/// "x*(x+1) is even"), guarding an always-taken jump to the real body with a dead, stack-neutral
/// junk block in between.
///
/// Because the predicate holds for ALL values of x, the jump is always taken and behavior is
/// unchanged - but since x is runtime-seeded the decompiler cannot prove the predicate, so it
/// cannot delete the bogus branch. The identity also varies per method, so there is no single
/// pattern for a cleaner such as de4dot to strip. Prepending keeps exception-handler boundaries
/// intact because the original first instruction retains its identity.
/// </summary>
public sealed class ControlFlowProtection : IProtection
{
    public string Name => "Control Flow";
    public bool IsEnabled(ObfuscationOptions o) => o.ControlFlow;

    private const int FieldCount = 4;

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;

        var holder = CilHelpers.CreateStaticHolder(module, ctx.Names.Next());
        var fields = new FieldDefinition[FieldCount];
        for (int i = 0; i < FieldCount; i++)
        {
            fields[i] = new FieldDefinition(ctx.Names.Next(),
                FieldAttributes.Public | FieldAttributes.Static, module.CorLibTypeFactory.Int32);
            holder.Fields.Add(fields[i]);
        }

        SeedFields(module, holder, fields, ctx);

        var methods = module.GetAllTypes()
            .SelectMany(t => t.Methods)
            .Where(m => m.CilMethodBody is { } b && b.Instructions.Count > 0)
            .ToList();

        int done = 0;
        foreach (var method in methods)
        {
            var instrs = method.CilMethodBody!.Instructions;
            var realFirst = instrs[0];
            var target = new CilInstructionLabel(realFirst);
            var field = fields[ctx.Rng.Next(FieldCount)];

            var prologue = new List<CilInstruction>();
            EmitAlwaysTruePredicate(prologue, field, target, ctx.Rng);
            EmitDeadJunk(prologue, field, ctx.Rng);

            for (int j = prologue.Count - 1; j >= 0; j--)
                instrs.Insert(0, prologue[j]);

            instrs.CalculateOffsets();
            done++;
        }

        ctx.Log.Step($"inserted opaque predicates into {done} method(s) using {FieldCount} runtime-seeded fields");
    }

    // Emits a static constructor that seeds each field from Environment.TickCount (a value the
    // decompiler cannot know), so the opaque predicates cannot be folded away.
    private static void SeedFields(ModuleDefinition module, TypeDefinition holder, FieldDefinition[] fields, ObfuscationContext ctx)
    {
        var tickCount = CilHelpers.ImportStatic(module, "System", "Environment", "get_TickCount",
            module.CorLibTypeFactory.Int32);

        var cctor = new MethodDefinition(".cctor",
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig
            | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName,
            MethodSignature.CreateStatic(module.CorLibTypeFactory.Void));
        holder.Methods.Add(cctor);

        var body = new CilMethodBody();
        cctor.CilMethodBody = body;
        var n = body.Instructions;
        foreach (var f in fields)
        {
            n.Add(new CilInstruction(CilOpCodes.Call, tickCount));
            n.Add(new CilInstruction(CilOpCodes.Ldc_I4, ctx.Rng.Next()));
            n.Add(new CilInstruction(CilOpCodes.Xor));
            n.Add(new CilInstruction(CilOpCodes.Stsfld, f));
        }
        n.Add(new CilInstruction(CilOpCodes.Ret));
        n.CalculateOffsets();
    }

    // Appends a predicate that is TRUE for every int value of the field, ending in a conditional
    // branch to 'target' that is therefore always taken.
    private static void EmitAlwaysTruePredicate(List<CilInstruction> n, FieldDefinition f, CilInstructionLabel target, Random rng)
    {
        switch (rng.Next(4))
        {
            case 0:
                // (x | 1) != 0  -> always non-zero -> brtrue always taken
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, f));
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
                n.Add(new CilInstruction(CilOpCodes.Or));
                n.Add(new CilInstruction(CilOpCodes.Brtrue, target));
                break;
            case 1:
                // x*(x+1) is even -> low bit == 0 -> brfalse always taken
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, f));
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, f));
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
                n.Add(new CilInstruction(CilOpCodes.Add));
                n.Add(new CilInstruction(CilOpCodes.Mul));
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
                n.Add(new CilInstruction(CilOpCodes.And));
                n.Add(new CilInstruction(CilOpCodes.Brfalse, target));
                break;
            case 2:
                // x*x - x = x*(x-1) is even -> low bit == 0 -> brfalse always taken
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, f));
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, f));
                n.Add(new CilInstruction(CilOpCodes.Mul));
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, f));
                n.Add(new CilInstruction(CilOpCodes.Sub));
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
                n.Add(new CilInstruction(CilOpCodes.And));
                n.Add(new CilInstruction(CilOpCodes.Brfalse, target));
                break;
            default:
                // (x >> 31) | 1  is -1 or 1, never 0 -> brtrue always taken
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, f));
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4_S, (sbyte)31));
                n.Add(new CilInstruction(CilOpCodes.Shr));
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
                n.Add(new CilInstruction(CilOpCodes.Or));
                n.Add(new CilInstruction(CilOpCodes.Brtrue, target));
                break;
        }
    }

    // A dead, stack-neutral block that never executes (the predicate above always branches away)
    // but looks like real work to a reader.
    private static void EmitDeadJunk(List<CilInstruction> n, FieldDefinition f, Random rng)
    {
        switch (rng.Next(3))
        {
            case 0:
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, f));
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4, rng.Next()));
                n.Add(new CilInstruction(CilOpCodes.Xor));
                n.Add(new CilInstruction(CilOpCodes.Pop));
                break;
            case 1:
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4, rng.Next()));
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4, rng.Next()));
                n.Add(new CilInstruction(CilOpCodes.Mul));
                n.Add(new CilInstruction(CilOpCodes.Pop));
                break;
            default:
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, f));
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, f));
                n.Add(new CilInstruction(CilOpCodes.Add));
                n.Add(new CilInstruction(CilOpCodes.Pop));
                break;
        }
    }
}
