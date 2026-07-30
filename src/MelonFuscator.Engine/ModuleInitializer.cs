using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine;

/// <summary>
/// Helper to get-or-create the module initializer (&lt;Module&gt;::.cctor), which the CLR
/// runs automatically the first time any type in the module is used - i.e. right when
/// MelonLoader instantiates the mod. We prepend calls to it so guards run early.
/// </summary>
public static class ModuleInitializer
{
    public static void CallFromModuleInitializer(ModuleDefinition module, MethodDefinition target)
    {
        var moduleType = module.GetOrCreateModuleType();

        var cctor = moduleType.GetStaticConstructor();
        if (cctor == null)
        {
            var sig = MethodSignature.CreateStatic(module.CorLibTypeFactory.Void);
            cctor = new MethodDefinition(".cctor",
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig
                | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName, sig);
            moduleType.Methods.Add(cctor);

            var body = new CilMethodBody();
            cctor.CilMethodBody = body;
            body.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
        }

        var instrs = cctor.CilMethodBody!.Instructions;
        // Insert the call at the very beginning so the guard runs first.
        instrs.Insert(0, new CilInstruction(CilOpCodes.Call, target));
        instrs.CalculateOffsets();
    }
}
