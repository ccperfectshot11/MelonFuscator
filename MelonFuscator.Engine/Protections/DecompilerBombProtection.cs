using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Decompiler bomb. Injects methods whose body is a deeply NESTED call expression
/// hb(ha(hc(...hd(x)))). A nested call expression cannot be folded (unlike an associative
/// a+a+a chain), so a structuring decompiler builds Call(Call(Call(...))) and recurses per
/// level -> StackOverflowException, which is uncatchable and crashes dnSpy/ILSpy.
///
/// Hardening against automated stripping:
///  - several distinct helper methods, chosen at random per call, so bombs are not a single
///    recognizable pattern;
///  - random depth per bomb;
///  - each bomb is REFERENCED from a real method behind an opaque-false guard, so it is not a
///    dead/unreferenced method a script can safely delete - and a decompiler that follows the
///    reference into the bomb crashes anyway.
///
/// It is valid IL the JIT would compile iteratively, and it is never actually executed (the
/// guard is always false at runtime), so it is runtime-safe; MelonLoader's verifier only
/// inspects names/metadata, which stay valid. Planted in every eligible top-level class.
/// </summary>
public sealed class DecompilerBombProtection : IProtection
{
    public string Name => "Decompiler Bomb";
    public bool IsEnabled(ObfuscationOptions o) => o.DecompilerBomb;

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var moduleType = module.GetModuleType();
        var f = module.CorLibTypeFactory;

        var holder = CilHelpers.CreateStaticHolder(module, ctx.Names.Next());

        // Opaque guard field (value 0). Used to reference bombs without ever executing them.
        var opaque = new FieldDefinition(ctx.Names.Next(),
            FieldAttributes.Public | FieldAttributes.Static, f.Int32);
        holder.Fields.Add(opaque);

        // Several distinct identity-ish helpers so nested chains aren't one recognizable shape.
        var helpers = new[]
        {
            EmitHelper(module, holder, ctx.Names.Next(), null, 0),
            EmitHelper(module, holder, ctx.Names.Next(), CilOpCodes.Xor, ctx.Rng.Next()),
            EmitHelper(module, holder, ctx.Names.Next(), CilOpCodes.Add, ctx.Rng.Next()),
            EmitHelper(module, holder, ctx.Names.Next(), CilOpCodes.Sub, ctx.Rng.Next()),
        };

        // Real methods we can hang bomb references off of (snapshot before adding bombs).
        var realMethods = module.GetAllTypes()
            .SelectMany(t => t.Methods)
            .Where(m => m.CilMethodBody is { } b && b.Instructions.Count > 0)
            .ToList();

        var targets = module.TopLevelTypes
            .Where(t => t != moduleType && t != holder && t.IsClass && !t.IsEnum && !t.IsInterface
                        && !(t.BaseType?.Name?.Value == "MulticastDelegate"))
            .ToList();

        int count = 0;
        foreach (var type in targets)
        {
            int depth = 1500 + ctx.Rng.Next(1500);
            var bomb = EmitBomb(module, type, ctx.Names.Next(), helpers, depth, ctx.Rng);

            // Reference the bomb from a random real method behind an always-false guard.
            if (realMethods.Count > 0)
                InjectGuardedReference(realMethods[ctx.Rng.Next(realMethods.Count)], opaque, bomb);

            count++;
        }
        ctx.Log.Step($"planted {count} varied, referenced decompiler bomb(s)");
    }

    // static int h(int a) => a <op> K;   (op == null => identity)
    private static MethodDefinition EmitHelper(ModuleDefinition module, TypeDefinition holder, string name,
        CilOpCode? op, int k)
    {
        var f = module.CorLibTypeFactory;
        var m = new MethodDefinition(name,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodSignature.CreateStatic(f.Int32, new TypeSignature[] { f.Int32 }));
        m.ImplAttributes |= MethodImplAttributes.NoInlining;
        holder.Methods.Add(m);

        var body = new CilMethodBody();
        m.CilMethodBody = body;
        var n = body.Instructions;
        n.Add(new CilInstruction(CilOpCodes.Ldarg_0));
        if (op != null)
        {
            n.Add(new CilInstruction(CilOpCodes.Ldc_I4, k));
            n.Add(new CilInstruction(op.Value));
        }
        n.Add(new CilInstruction(CilOpCodes.Ret));
        body.Instructions.CalculateOffsets();
        return m;
    }

    // static int Bomb(int x) => hb(ha(hc(...hd(x))));
    private static MethodDefinition EmitBomb(ModuleDefinition module, TypeDefinition type, string name,
        MethodDefinition[] helpers, int depth, Random rng)
    {
        var f = module.CorLibTypeFactory;
        var m = new MethodDefinition(name,
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodSignature.CreateStatic(f.Int32, new TypeSignature[] { f.Int32 }));
        type.Methods.Add(m);

        var body = new CilMethodBody();
        m.CilMethodBody = body;
        var n = body.Instructions;
        n.Add(new CilInstruction(CilOpCodes.Ldarg_0));
        for (int i = 0; i < depth; i++)
            n.Add(new CilInstruction(CilOpCodes.Call, helpers[rng.Next(helpers.Length)]));
        n.Add(new CilInstruction(CilOpCodes.Ret));
        body.Instructions.CalculateOffsets();
        return m;
    }

    // Prepend: if (opaque != 0) { Bomb(0); }   -- always false at runtime, but a real reference.
    private static void InjectGuardedReference(MethodDefinition host, FieldDefinition opaque, MethodDefinition bomb)
    {
        var instrs = host.CilMethodBody!.Instructions;
        var realFirst = instrs[0];
        var prologue = new List<CilInstruction>
        {
            new CilInstruction(CilOpCodes.Ldsfld, opaque),
            new CilInstruction(CilOpCodes.Brfalse, new CilInstructionLabel(realFirst)),
            new CilInstruction(CilOpCodes.Ldc_I4_0),
            new CilInstruction(CilOpCodes.Call, bomb),
            new CilInstruction(CilOpCodes.Pop),
        };
        for (int j = prologue.Count - 1; j >= 0; j--)
            instrs.Insert(0, prologue[j]);
        instrs.CalculateOffsets();
    }
}
