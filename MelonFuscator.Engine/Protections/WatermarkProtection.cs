using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Runs LAST (after renaming) so the injected type names survive.
///  - Watermark: [module: MelonedBy("MelonFuscator.vX.Y.Z")], like ConfuserEx's ConfusedBy.
///  - Anti-de4dot: injects fake obfuscator-marker attributes (ConfusedBy, Dotfuscator,
///    BabelObfuscator, ...) so de4dot mis-detects the protector and applies the wrong
///    cleanup profile. Only valid identifier names are used, so MelonLoader's verifier passes.
/// </summary>
public sealed class WatermarkProtection : IProtection
{
    public string Name => "Watermark + Anti-de4dot markers";
    public bool IsEnabled(ObfuscationOptions o) => true; // watermark always on

    // Well-known obfuscator marker attributes de4dot looks for. Valid identifiers only.
    private static readonly (string ns, string name)[] FakeMarkers =
    {
        ("SmartAssembly.Attributes", "PoweredByAttribute"),
        ("", "ConfusedByAttribute"),
        ("SecureTeam.Attributes", "ObfuscatedByAgileDotNetAttribute"),
        ("SecureTeam.Attributes", "ObfuscatedByCliSecureAttribute"),
        ("", "DotfuscatorAttribute"),
        ("", "BabelObfuscatorAttribute"),
        ("NineRays.Obfuscator", "EvaluationAttribute"),
        ("CryptoObfuscator", "ProtectedWithCryptoObfuscatorAttribute"),
        ("", "ZYXDNGuarderAttribute"),
    };

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;

        // Watermark.
        var wmType = InjectAttributeType(module, null, "MelonedByAttribute", withStringArg: true);
        ApplyModuleAttribute(module, wmType, MelonFuscatorInfo.Watermark);

        int markers = 0;
        if (ctx.Options.AntiDecompiler)
        {
            foreach (var (ns, name) in FakeMarkers)
            {
                var t = InjectAttributeType(module, string.IsNullOrEmpty(ns) ? null : ns, name, withStringArg: false);
                ApplyModuleAttribute(module, t, null);
                markers++;
            }
        }

        ctx.Log.Step($"watermark '{MelonFuscatorInfo.Watermark}' + {markers} decoy obfuscator marker(s)");
    }

    // Creates: class <name> : System.Attribute { public <name>([string s]) : base() {} }
    private static TypeDefinition InjectAttributeType(ModuleDefinition module, string? ns, string name, bool withStringArg)
    {
        var attrBase = CilHelpers.CorLibType(module, "System", "Attribute");
        var t = new TypeDefinition(ns, name,
            TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.BeforeFieldInit, attrBase);
        module.TopLevelTypes.Add(t);

        var pars = withStringArg
            ? new TypeSignature[] { module.CorLibTypeFactory.String }
            : System.Array.Empty<TypeSignature>();
        var ctorSig = MethodSignature.CreateInstance(module.CorLibTypeFactory.Void, pars);
        var ctor = new MethodDefinition(".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig
            | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName, ctorSig);
        t.Methods.Add(ctor);

        var baseCtor = (IMethodDefOrRef)module.DefaultImporter.ImportMethod(
            new MemberReference(attrBase, ".ctor", MethodSignature.CreateInstance(module.CorLibTypeFactory.Void)));

        var body = new CilMethodBody();
        ctor.CilMethodBody = body;
        body.Instructions.Add(new CilInstruction(CilOpCodes.Ldarg_0));
        body.Instructions.Add(new CilInstruction(CilOpCodes.Call, baseCtor));
        body.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
        body.Instructions.CalculateOffsets();
        return t;
    }

    private static void ApplyModuleAttribute(ModuleDefinition module, TypeDefinition attrType, string? stringArg)
    {
        var ctor = attrType.Methods.First(m => m.IsConstructor);
        var sig = new CustomAttributeSignature();
        if (stringArg != null)
            sig.FixedArguments.Add(new CustomAttributeArgument(module.CorLibTypeFactory.String, stringArg));
        module.CustomAttributes.Add(new CustomAttribute((ICustomAttributeType)ctor, sig));
    }
}
