using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Decompiler bomb. Injects never-called methods whose body is a deeply NESTED call
/// expression: h(h(h(...h(x)))). Unlike an associative a+a+a chain (which ILSpy folds
/// iteratively), a nested call expression cannot be flattened, so a structuring decompiler
/// builds Call(Call(Call(...))) and recurses per level -> StackOverflowException, which is
/// uncatchable and crashes dnSpy/ILSpy.
///
/// It is valid IL the JIT would compile iteratively, and it is never called (never JIT'd),
/// so it is runtime-safe; MelonLoader's verifier only inspects names/metadata, which stay
/// valid. A bomb is planted in every eligible top-level class, so opening anything crashes
/// the tool.
/// </summary>
public sealed class DecompilerBombProtection : IProtection
{
    public string Name => "Decompiler Bomb";
    public bool IsEnabled(ObfuscationOptions o) => o.DecompilerBomb;

    private const int Depth = 3000; // nested call frames; well past any decompiler's stack

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var moduleType = module.GetModuleType();

        // One shared identity helper that all bombs call, nested.
        var holder = CilHelpers.CreateStaticHolder(module, ctx.Names.Next());
        var helper = EmitHelper(module, holder, ctx.Names.Next());

        var targets = module.TopLevelTypes
            .Where(t => t != moduleType && t != holder && t.IsClass && !t.IsEnum && !t.IsInterface
                        && !(t.BaseType?.Name?.Value == "MulticastDelegate"))
            .ToList();

        int count = 0;
        foreach (var type in targets)
        {
            EmitBomb(module, type, ctx.Names.Next(), helper);
            count++;
        }
        ctx.Log.Step($"planted {count} nested-call decompiler bomb(s) (depth {Depth})");
    }

    // static int h(int a) => a;  (never called at runtime)
    private static MethodDefinition EmitHelper(ModuleDefinition module, TypeDefinition holder, string name)
    {
        var f = module.CorLibTypeFactory;
        var m = new MethodDefinition(name,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodSignature.CreateStatic(f.Int32, new TypeSignature[] { f.Int32 }));
        // NoInlining so a decompiler never elides the call and always sees the nesting.
        m.ImplAttributes |= MethodImplAttributes.NoInlining;
        holder.Methods.Add(m);

        var body = new CilMethodBody();
        m.CilMethodBody = body;
        body.Instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
        body.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
        body.Instructions.CalculateOffsets();
        return m;
    }

    // static int Bomb(int x) => h(h(h(...h(x))));  (never called at runtime)
    private static void EmitBomb(ModuleDefinition module, TypeDefinition type, string name, MethodDefinition helper)
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
        for (int i = 0; i < Depth; i++)
            n.Add(new CilInstruction(CilOpCodes.Call, helper));  // h(previous)
        n.Add(new CilInstruction(CilOpCodes.Ret));
        body.Instructions.CalculateOffsets();
    }
}
