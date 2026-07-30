using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Decompiler bomb. Injects never-called methods whose body is a single, enormous, deeply
/// nested expression tree (x + x + x + ... on a parameter, so it cannot be constant-folded).
///
/// Structuring decompilers (ICSharpCode / dnSpy / ILSpy) build an AST and walk it recursively;
/// a tree this deep overflows their call stack -> StackOverflowException, which is uncatchable
/// and takes the whole decompiler down. The CLR never touches it: the method is never called,
/// so it is never JIT-compiled, and MelonLoader's verifier only inspects names/metadata (which
/// are perfectly valid here). Placed on the melon entry type + a random sample of other types,
/// so opening almost anything in the mod crashes the tool.
/// </summary>
public sealed class DecompilerBombProtection : IProtection
{
    public string Name => "Decompiler Bomb";
    public bool IsEnabled(ObfuscationOptions o) => o.DecompilerBomb;

    private const int Depth = 10000; // ~20 KB of IL; far past any decompiler's recursion limit

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var moduleType = module.GetModuleType();

        // Targets: the melon entry types + a random sample of other top-level classes.
        var targets = new HashSet<TypeDefinition>(ctx.Analysis.MelonTypes);
        var pool = module.TopLevelTypes
            .Where(t => t != moduleType && t.IsClass && !t.IsEnum && !t.IsInterface
                        && !(t.BaseType?.Name?.Value == "MulticastDelegate"))
            .ToList();
        for (int i = 0; i < 8 && pool.Count > 0; i++)
            targets.Add(pool[ctx.Rng.Next(pool.Count)]);

        int count = 0;
        foreach (var type in targets)
        {
            EmitBomb(module, type, ctx.Names.Next());
            count++;
        }
        ctx.Log.Step($"planted {count} decompiler bomb(s) (nesting depth {Depth})");
    }

    private static void EmitBomb(ModuleDefinition module, TypeDefinition type, string name)
    {
        var f = module.CorLibTypeFactory;
        var sig = MethodSignature.CreateStatic(f.Int32, new TypeSignature[] { f.Int32 });
        var m = new MethodDefinition(name,
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig, sig);
        type.Methods.Add(m);

        var body = new CilMethodBody();
        m.CilMethodBody = body;
        var n = body.Instructions;

        // (x + x + x + ... ) with Depth additions - a right-leaning tree of depth ~Depth.
        n.Add(new CilInstruction(CilOpCodes.Ldarg_0));
        for (int i = 0; i < Depth; i++)
        {
            n.Add(new CilInstruction(CilOpCodes.Ldarg_0));
            n.Add(new CilInstruction(CilOpCodes.Add));
        }
        n.Add(new CilInstruction(CilOpCodes.Ret));

        // maxstack is only 2 here (accumulator + one operand), so this stays cheap to load.
        body.ComputeMaxStackOnBuild = true;
        body.Instructions.CalculateOffsets();
    }
}
