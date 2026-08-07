using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Call proxying (anti-de4dot / call-graph obfuscation). Every 'call' to an external
/// static method is rerouted through a generated proxy method that simply forwards the
/// arguments. This hides direct references to BCL/Unity/MelonLoader methods and breaks
/// tools that reason about the call graph. Only safe, non-generic static calls are proxied.
/// </summary>
public sealed class ProxyCallProtection : IProtection
{
    public string Name => "Proxy Calls";
    public bool IsEnabled(ObfuscationOptions o) => o.ProxyCalls;

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var holder = CilHelpers.CreateStaticHolder(module, ctx.Names.Next());
        var cache = new Dictionary<string, MethodDefinition>(StringComparer.Ordinal);

        // Snapshot bodies BEFORE adding proxies so we never reprocess generated methods.
        var methods = module.GetAllTypes()
            .SelectMany(t => t.Methods)
            .Where(m => m.CilMethodBody != null)
            .ToList();

        int redirected = 0;
        foreach (var method in methods)
        {
            var instrs = method.CilMethodBody!.Instructions;
            for (int i = 0; i < instrs.Count; i++)
            {
                var ins = instrs[i];
                if (ins.OpCode.Code != CilCode.Call)
                    continue;

                if (ins.Operand is not IMethodDefOrRef target)
                    continue;
                if (target is MethodSpecification)
                    continue;
                if (target.Signature is not MethodSignature msig)
                    continue;
                if (msig.HasThis || msig.GenericParameterCount > 0)
                    continue;
                if (target.DeclaringType is TypeSpecification)
                    continue;
                if (!IsExternal(module, target))
                    continue;

                try
                {
                    var proxy = GetOrCreateProxy(module, holder, cache, target, msig, ctx);
                    ins.Operand = proxy;
                    redirected++;
                }
                catch
                {
                    // If anything about this signature is unusual, leave the call untouched.
                }
            }
        }

        int fieldReads = ProxyStaticFieldReads(module, holder, methods, ctx);
        ctx.Log.Step($"created {cache.Count} call proxies (redirected {redirected}), {fieldReads} static field read(s) via accessors");
    }

    // Replaces 'ldsfld F' on in-module static fields with a call to a generated getter, hiding
    // which fields are read where. Reads only (getters) - never touches writes, so 'initonly'
    // fields stay valid. The field is widened to public so the accessor can read it.
    private static int ProxyStaticFieldReads(ModuleDefinition module, TypeDefinition holder,
        List<MethodDefinition> methods, ObfuscationContext ctx)
    {
        var getters = new Dictionary<FieldDefinition, MethodDefinition>();
        int redirected = 0;

        foreach (var method in methods)
        {
            var instrs = method.CilMethodBody!.Instructions;
            for (int i = 0; i < instrs.Count; i++)
            {
                var ins = instrs[i];
                if (ins.OpCode.Code != CilCode.Ldsfld) continue;
                // Only in-module fields (FieldDefinition), i.e. ones we can widen + read safely.
                if (ins.Operand is not FieldDefinition f) continue;
                if (f.DeclaringType?.DeclaringModule != module) continue;
                if (f.Signature is null) continue;

                try
                {
                    var getter = GetOrCreateGetter(module, holder, getters, f, ctx);
                    ins.OpCode = CilOpCodes.Call;
                    ins.Operand = getter;
                    redirected++;
                }
                catch
                {
                    // Leave the access untouched on anything unexpected.
                }
            }
        }
        return redirected;
    }

    private static MethodDefinition GetOrCreateGetter(ModuleDefinition module, TypeDefinition holder,
        Dictionary<FieldDefinition, MethodDefinition> getters, FieldDefinition f, ObfuscationContext ctx)
    {
        if (getters.TryGetValue(f, out var existing)) return existing;

        // Widen visibility so the accessor (in another type) can legally read the field.
        f.Attributes = (f.Attributes & ~FieldAttributes.FieldAccessMask) | FieldAttributes.Public;

        var sig = MethodSignature.CreateStatic(f.Signature!.FieldType);
        var getter = new MethodDefinition(ctx.Names.Next(),
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, sig);
        holder.Methods.Add(getter);

        var body = new CilMethodBody();
        getter.CilMethodBody = body;
        body.Instructions.Add(new CilInstruction(CilOpCodes.Ldsfld, f));
        body.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
        body.Instructions.CalculateOffsets();

        getters[f] = getter;
        return getter;
    }

    private static bool IsExternal(ModuleDefinition module, IMethodDefOrRef target)
    {
        // In-module calls carry a MethodDefinition operand; anything referenced through a
        // MemberReference/MethodSpecification points outside this module. This avoids calling
        // Resolve() (which throws on missing dependency assemblies) on a hot path.
        if (target is MethodDefinition md)
            return md.DeclaringType?.DeclaringModule != module;
        return true;
    }

    private static MethodDefinition GetOrCreateProxy(ModuleDefinition module, TypeDefinition holder,
        Dictionary<string, MethodDefinition> cache, IMethodDefOrRef target, MethodSignature msig, ObfuscationContext ctx)
    {
        var keyStr = target.DeclaringType?.FullName + "::" + target.Name + msig;
        if (cache.TryGetValue(keyStr, out var existing))
            return existing;

        var pars = msig.ParameterTypes.ToArray();
        var proxySig = MethodSignature.CreateStatic(msig.ReturnType, pars);
        var proxy = new MethodDefinition(ctx.Names.Next(),
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, proxySig);
        holder.Methods.Add(proxy);

        var body = new CilMethodBody();
        proxy.CilMethodBody = body;
        var n = body.Instructions;

        // Forward via an indirect call (ldftn + calli) instead of a direct 'call'. This turns the
        // call edge into a function-pointer invocation, hiding it from naive call-graph analysis
        // and breaking de4dot's "simple forwarder" proxy remover.
        foreach (var p in proxy.Parameters)
            n.Add(new CilInstruction(CilOpCodes.Ldarg, p));
        n.Add(new CilInstruction(CilOpCodes.Ldftn, target));
        n.Add(new CilInstruction(CilOpCodes.Calli, new StandAloneSignature(
            MethodSignature.CreateStatic(msig.ReturnType, msig.ParameterTypes.ToArray()))));
        n.Add(new CilInstruction(CilOpCodes.Ret));
        body.Instructions.CalculateOffsets();

        cache[keyStr] = proxy;
        return proxy;
    }
}
