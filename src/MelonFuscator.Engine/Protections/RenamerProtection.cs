using AsmResolver.DotNet;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Entropy-aware renamer. Renames types, methods, fields, properties, events and
/// parameters to random names drawn from a controlled alphabet so the resulting
/// character distribution lands inside MelonLoader's required entropy window [4.0, 5.5].
///
/// In-module references update automatically because AsmResolver targets the
/// definition objects directly; external references (MelonLoader/Unity/BCL) are left intact.
/// </summary>
public sealed class RenamerProtection : IProtection
{
    public string Name => "Renamer";
    public bool IsEnabled(ObfuscationOptions o) => o.Rename;

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var names = ctx.Names;
        var analysis = ctx.Analysis;

        int renamedTypes = 0, renamedMethods = 0, renamedFields = 0, renamedProps = 0, renamedEvents = 0;

        // Capture (attribute, index -> in-module type) BEFORE renaming so we can repair the
        // name-based System.Type blob arguments afterwards.
        var typeArgFixups = CaptureTypeArgumentFixups(ctx);

        var moduleType = module.GetModuleType();

        foreach (var type in module.GetAllTypes())
        {
            if (type == moduleType)
                continue; // never touch <Module>

            bool unityDerived = InheritsFromUnityBase(type, module);

            // --- Methods ---
            foreach (var method in type.Methods)
            {
                if (!ShouldRenameMethod(method, analysis))
                    continue;

                method.Name = names.Next();
                renamedMethods++;

                // Parameter names are cosmetic and not checked by the verifier; strip them.
                foreach (var p in method.ParameterDefinitions)
                    p.Name = "";
            }

            // --- Fields ---
            foreach (var field in type.Fields)
            {
                if (!ShouldRenameField(field, type, unityDerived, analysis))
                    continue;

                field.Name = names.Next();
                renamedFields++;
            }

            // --- Properties ---
            foreach (var prop in type.Properties)
            {
                if (IsAccessorProtected(prop.GetMethod, analysis) || IsAccessorProtected(prop.SetMethod, analysis))
                    continue;
                prop.Name = names.Next();
                renamedProps++;
            }

            // --- Events ---
            foreach (var evt in type.Events)
            {
                if (IsAccessorProtected(evt.AddMethod, analysis) || IsAccessorProtected(evt.RemoveMethod, analysis))
                    continue;
                evt.Name = names.Next();
                renamedEvents++;
            }

            // --- Type name + namespace ---
            type.Namespace = null;                // collapse all namespaces to global
            type.Name = names.Next();
            renamedTypes++;
        }

        // CRITICAL for MelonLoader: System.Type arguments in custom attributes (e.g. the
        // typeof(Mod) inside MelonInfoAttribute) are serialized in the blob as the type's
        // name string, NOT as a token. Renaming the type does not update that string, which
        // would make MelonLoader fail to resolve info.SystemType. Rewrite those arguments
        // so they point at the renamed types.
        int fixedArgs = ApplyTypeArgumentFixups(typeArgFixups);
        if (fixedArgs > 0)
            ctx.Log.Step($"repaired {fixedArgs} System.Type attribute argument(s) after rename");

        ctx.Log.Step($"renamed {renamedTypes} types, {renamedMethods} methods, {renamedFields} fields, " +
                     $"{renamedProps} properties, {renamedEvents} events");
        ctx.Log.Step($"alphabet size {names.AlphabetSize} -> theoretical entropy {names.TheoreticalEntropy:F3}");
    }

    private static bool ShouldRenameMethod(MethodDefinition m, MelonAnalysis analysis)
    {
        if (analysis.ProtectedMethods.Contains(m)) return false;
        if (m.IsConstructor) return false;              // .ctor / .cctor
        if (m.IsRuntimeSpecialName) return false;       // runtime-critical special names
        if (m.IsVirtual) return false;                  // overrides + interface impls + new virtuals -> vtable safety
        if (m.IsPInvokeImpl) return false;              // native entry point often equals method name
        if (m.Name is not null && ReservedNames.UnityMagicMethods.Contains(m.Name)) return false;
        return true;
    }

    private static bool ShouldRenameField(FieldDefinition f, TypeDefinition declaringType, bool unityDerived, MelonAnalysis analysis)
    {
        if (analysis.ProtectedFields.Contains(f)) return false;
        if (f.IsRuntimeSpecialName) return false;       // e.g. enum value__
        if (declaringType.IsEnum) return false;         // enum member names are often used via ToString/Parse
        // Instance fields on Unity-serializable types may be serialized by name -> keep them.
        if (unityDerived && !f.IsStatic) return false;
        return true;
    }

    private static bool IsAccessorProtected(MethodDefinition? accessor, MelonAnalysis analysis)
    {
        if (accessor == null) return false;
        if (analysis.ProtectedMethods.Contains(accessor)) return true;
        if (accessor.IsVirtual) return true;
        if (accessor.Name is not null && ReservedNames.UnityMagicMethods.Contains(accessor.Name)) return true;
        return false;
    }

    // One System.Type attribute argument that must be repaired after renaming.
    private sealed record TypeArgFixup(AsmResolver.DotNet.Signatures.CustomAttributeSignature Sig, int Index, bool IsNamed, TypeDefinition Target);

    private static List<TypeArgFixup> CaptureTypeArgumentFixups(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var rc = module.RuntimeContext;
        var inModule = new HashSet<TypeDefinition>(module.GetAllTypes());
        var result = new List<TypeArgFixup>();

        void Scan(IEnumerable<CustomAttribute> attrs)
        {
            foreach (var ca in attrs)
            {
                var sig = ca.Signature;
                if (sig == null) continue;

                // Reading FixedArguments forces the blob to be parsed. If it contains a
                // typeof() of an unresolvable (e.g. Il2Cpp generic) type, parsing throws.
                // Such attributes reference only external types, so we skip them and let
                // AsmResolver write their original blob verbatim.
                try
                {
                    for (int i = 0; i < sig.FixedArguments.Count; i++)
                    {
                        if (TryResolveTypeArg(sig.FixedArguments[i], rc, inModule, out var td))
                            result.Add(new TypeArgFixup(sig, i, false, td!));
                    }
                    for (int i = 0; i < sig.NamedArguments.Count; i++)
                    {
                        if (TryResolveTypeArg(sig.NamedArguments[i].Argument, rc, inModule, out var td))
                            result.Add(new TypeArgFixup(sig, i, true, td!));
                    }
                }
                catch
                {
                    // Unparseable attribute blob (external typeof) -> leave it untouched.
                }
            }
        }

        if (module.Assembly != null) Scan(module.Assembly.CustomAttributes);
        Scan(module.CustomAttributes);
        foreach (var type in module.GetAllTypes())
        {
            Scan(type.CustomAttributes);
            foreach (var m in type.Methods) Scan(m.CustomAttributes);
            foreach (var f in type.Fields) Scan(f.CustomAttributes);
            foreach (var p in type.Properties) Scan(p.CustomAttributes);
            foreach (var e in type.Events) Scan(e.CustomAttributes);
        }
        return result;
    }

    private static bool TryResolveTypeArg(AsmResolver.DotNet.Signatures.CustomAttributeArgument arg,
        AsmResolver.DotNet.RuntimeContext rc, HashSet<TypeDefinition> inModule, out TypeDefinition? td)
    {
        td = null;
        if (arg.Element is AsmResolver.DotNet.Signatures.TypeSignature ts)
        {
            var resolved = CilHelpers.SafeResolve(ts.GetUnderlyingTypeDefOrRef(), rc);
            if (resolved != null && inModule.Contains(resolved))
            {
                td = resolved;
                return true;
            }
        }
        return false;
    }

    private static int ApplyTypeArgumentFixups(List<TypeArgFixup> fixups)
    {
        int count = 0;
        foreach (var f in fixups)
        {
            // Build the signature explicitly as a reference type. We must NOT use the
            // parameterless ToTypeSignature(), which tries to determine value-type-ness by
            // resolving the (possibly Il2Cpp/unavailable) base chain and throws. For the
            // custom-attribute blob only the type name string matters, so the class/valuetype
            // flag is irrelevant here.
            var targetSig = new AsmResolver.DotNet.Signatures.TypeDefOrRefSignature(f.Target, false);

            if (f.IsNamed)
            {
                var na = f.Sig.NamedArguments[f.Index];
                var rebuilt = new AsmResolver.DotNet.Signatures.CustomAttributeArgument(
                    na.Argument.ArgumentType, targetSig);
                f.Sig.NamedArguments[f.Index] = new AsmResolver.DotNet.Signatures.CustomAttributeNamedArgument(
                    na.MemberType, na.MemberName, na.ArgumentType, rebuilt);
            }
            else
            {
                var old = f.Sig.FixedArguments[f.Index];
                f.Sig.FixedArguments[f.Index] = new AsmResolver.DotNet.Signatures.CustomAttributeArgument(
                    old.ArgumentType, targetSig);
            }
            count++;
        }
        return count;
    }

    private static bool InheritsFromUnityBase(TypeDefinition type, AsmResolver.DotNet.ModuleDefinition module)
    {
        AsmResolver.DotNet.ITypeDefOrRef? current = type.BaseType;
        int guard = 0;
        while (current != null && guard++ < 50)
        {
            if (current.Name is not null && ReservedNames.UnityBaseTypeNames.Contains(current.Name))
                return true;

            // Only follow in-module bases; external bases are name-checked then we stop,
            // so we never resolve unavailable dependency assemblies (which would throw).
            if (current is TypeDefinition td)
                current = td.BaseType;
            else
                break;
        }
        return false;
    }
}
