using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;

namespace MelonFuscator.Engine;
// Note: Resolve(...) needs a RuntimeContext in AsmResolver 6.x, so we thread module.RuntimeContext through.

/// <summary>
/// Inspects the target assembly to detect that it is a MelonLoader mod and to build
/// the set of members that must never be renamed/altered so the mod keeps loading.
/// </summary>
public static class MelonLoaderAnalyzer
{
    private const string MelonNamespace = "MelonLoader";

    public static void Analyze(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var analysis = ctx.Analysis;

        // 1) Find MelonInfoAttribute on the assembly and resolve its SystemType argument.
        if (module.Assembly != null)
        {
            foreach (var ca in module.Assembly.CustomAttributes)
            {
                var declType = ca.Constructor?.DeclaringType;
                if (declType == null)
                    continue;

                if (declType.Name?.Value == "MelonInfoAttribute" ||
                    declType.Name?.Value == "MelonModInfoAttribute" ||
                    declType.Name?.Value == "MelonPluginInfoAttribute")
                {
                    analysis.IsMelonAssembly = true;

                    var modType = ResolveFirstTypeArg(ca, module);
                    if (modType != null && !analysis.MelonTypes.Contains(modType))
                    {
                        analysis.MelonTypes.Add(modType);
                        analysis.ProtectedTypes.Add(modType);
                        ctx.Log.Step($"Melon entry type: {modType.FullName}");
                    }
                }
            }
        }

        // 2) Fallback: detect types inheriting MelonMod/MelonPlugin even without the attribute.
        foreach (var type in module.GetAllTypes())
        {
            if (InheritsFrom(type, "MelonMod") || InheritsFrom(type, "MelonPlugin"))
            {
                analysis.IsMelonAssembly = true;
                if (!analysis.MelonTypes.Contains(type))
                {
                    analysis.MelonTypes.Add(type);
                    analysis.ProtectedTypes.Add(type);
                }
            }

            // 3) Protect explicit interface implementations (invoked via slot, name matters
            //    for the interface map on some runtimes).
            foreach (var impl in type.MethodImplementations)
            {
                var body = CilHelpers.SafeResolve(impl.Body, module.RuntimeContext);
                if (body != null)
                    analysis.ProtectedMethods.Add(body);
            }
        }
    }

    // Reads the first constructor argument of the attribute as a Type and resolves it.
    private static TypeDefinition? ResolveFirstTypeArg(CustomAttribute ca, ModuleDefinition module)
    {
        var sig = ca.Signature;
        if (sig == null || sig.FixedArguments.Count == 0)
            return null;

        var element = sig.FixedArguments[0].Element;
        switch (element)
        {
            case TypeSignature ts:
                return CilHelpers.SafeResolve(ts.GetUnderlyingTypeDefOrRef(), module.RuntimeContext);
            case ITypeDefOrRef tr:
                return CilHelpers.SafeResolve(tr, module.RuntimeContext);
            default:
                return null;
        }
    }

    // Walks the base-type chain looking for a base type with the given simple name.
    // We only follow in-module bases (TypeDefinition); an external base is name-checked
    // and then we stop, so we never touch unavailable dependency assemblies.
    private static bool InheritsFrom(TypeDefinition type, string baseSimpleName)
    {
        ITypeDefOrRef? current = type.BaseType;
        int guard = 0;
        while (current != null && guard++ < 50)
        {
            if (current.Name?.Value == baseSimpleName)
                return true;

            if (current is TypeDefinition td)
                current = td.BaseType;
            else
                break;
        }
        return false;
    }
}
