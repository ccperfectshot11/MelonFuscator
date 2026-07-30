using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Decompiler bomb. Injects methods whose body is a deeply NESTED expression built from
/// random helper calls interleaved with real arithmetic - h(h(x)+K ^ h(...)). A nested
/// expression cannot be folded, so a structuring decompiler builds a giant recursive AST and
/// StackOverflows, crashing dnSpy/ILSpy.
///
/// Hardened against automated identification/stripping:
///  - four distinct helper methods, chosen at random per node (no single-helper signature);
///  - the chain is interleaved with real arithmetic so it doesn't look like a pure call loop;
///  - random depth per bomb;
///  - each bomb is referenced from a real method behind an always-false predicate, and those
///    predicates VARY (A, A&gt;C, A*A&lt;0, (A|1)==0 over several opaque fields) so there is no
///    single guard pattern to grep for; the bomb is therefore not a dead/unreferenced method
///    a script can delete, and following the reference into it crashes the decompiler anyway.
///
/// Runtime-safe: the guard is always false so the bomb is never called (never JIT'd), and it
/// is valid IL regardless; MelonLoader's verifier only inspects names/metadata.
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

        // Several opaque fields (all 0). Used by varied always-false guards.
        var fields = new FieldDefinition[4];
        for (int i = 0; i < fields.Length; i++)
        {
            fields[i] = new FieldDefinition(ctx.Names.Next(),
                FieldAttributes.Public | FieldAttributes.Static, f.Int32);
            holder.Fields.Add(fields[i]);
        }

        var helpers = new[]
        {
            EmitHelper(module, holder, ctx.Names.Next(), null, 0),
            EmitHelper(module, holder, ctx.Names.Next(), CilOpCodes.Xor, ctx.Rng.Next()),
            EmitHelper(module, holder, ctx.Names.Next(), CilOpCodes.Add, ctx.Rng.Next()),
            EmitHelper(module, holder, ctx.Names.Next(), CilOpCodes.Sub, ctx.Rng.Next()),
        };

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
            int depth = 600 + ctx.Rng.Next(900);
            var bomb = EmitBomb(module, type, ctx.Names.Next(), helpers, depth, ctx.Rng);
            if (realMethods.Count > 0)
                InjectGuardedReference(realMethods[ctx.Rng.Next(realMethods.Count)], fields, bomb, ctx.Rng);
            count++;
        }
        ctx.Log.Step($"planted {count} varied, referenced decompiler bomb(s)");
    }

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
        var arith = new[] { CilOpCodes.Add, CilOpCodes.Xor, CilOpCodes.Sub, CilOpCodes.Mul };
        for (int i = 0; i < depth; i++)
        {
            n.Add(new CilInstruction(CilOpCodes.Call, helpers[rng.Next(helpers.Length)]));
            if (rng.Next(20) == 0) // occasionally fold in real arithmetic so it isn't a pure call chain
            {
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4, rng.Next()));
                n.Add(new CilInstruction(arith[rng.Next(arith.Length)]));
            }
        }
        n.Add(new CilInstruction(CilOpCodes.Ret));
        body.Instructions.CalculateOffsets();
        return m;
    }

    // Prepend: if (<always-false varied predicate>) { Bomb(0); }
    private static void InjectGuardedReference(MethodDefinition host, FieldDefinition[] fields,
        MethodDefinition bomb, Random rng)
    {
        var instrs = host.CilMethodBody!.Instructions;
        var realFirst = instrs[0];

        var prologue = new List<CilInstruction>();
        EmitFalsePredicate(prologue, fields, rng);                       // leaves 0 on the stack
        prologue.Add(new CilInstruction(CilOpCodes.Brfalse, new CilInstructionLabel(realFirst)));
        prologue.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        prologue.Add(new CilInstruction(CilOpCodes.Call, bomb));
        prologue.Add(new CilInstruction(CilOpCodes.Pop));

        for (int j = prologue.Count - 1; j >= 0; j--)
            instrs.Insert(0, prologue[j]);
        instrs.CalculateOffsets();
    }

    // Emits a predicate that is always 0 (false) at runtime but is not a single grep-able shape.
    private static void EmitFalsePredicate(List<CilInstruction> n, FieldDefinition[] fields, Random rng)
    {
        var a = fields[rng.Next(fields.Length)];
        var c = fields[rng.Next(fields.Length)];
        switch (rng.Next(4))
        {
            case 0: // A            (0)
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, a));
                break;
            case 1: // A > C        (0 > 0 == false)
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, a));
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, c));
                n.Add(new CilInstruction(CilOpCodes.Cgt));
                break;
            case 2: // A*A < 0      (a square is never negative)
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, a));
                n.Add(new CilInstruction(CilOpCodes.Dup));
                n.Add(new CilInstruction(CilOpCodes.Mul));
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
                n.Add(new CilInstruction(CilOpCodes.Clt));
                break;
            default: // (A | 1) == 0  (odd is never zero)
                n.Add(new CilInstruction(CilOpCodes.Ldsfld, a));
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
                n.Add(new CilInstruction(CilOpCodes.Or));
                n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
                n.Add(new CilInstruction(CilOpCodes.Ceq));
                break;
        }
    }
}
