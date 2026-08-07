using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine;

/// <summary>
/// Helpers that build references to core-library members using the TARGET module's own
/// corlib scope. This is essential for cross-runtime portability: a reference built this
/// way resolves on Unity Mono (mscorlib) as well as IL2CPP/CoreCLR (System.Private.CoreLib).
/// </summary>
public static class CilHelpers
{
    /// <summary>
    /// True for the nested types the C# compiler emits for iterators (`&lt;Method&gt;d__N`
    /// implementing IEnumerator) and async methods (implementing IAsyncStateMachine). Their MoveNext
    /// resumes by switching on this.&lt;&gt;1__state into the middle of the method, an implicit protocol
    /// that structural rewrites (flattening, opaque predicates, constant/arithmetic/local encoding,
    /// call proxying) cannot see - touching them yields IL that verifies but throws
    /// InvalidProgramException the moment the JIT runs it. Every body-rewriting protection skips these.
    /// Detected by interface, not name, so it survives renaming and holds whatever the type is called.
    /// </summary>
    public static bool IsCompilerStateMachine(TypeDefinition type)
    {
        foreach (var impl in type.Interfaces)
        {
            var n = impl.Interface?.Name?.Value;
            var ns = impl.Interface?.Namespace?.Value;
            if (ns == "System.Runtime.CompilerServices" && n == "IAsyncStateMachine") return true;
            if (ns == "System.Collections" && n == "IEnumerator") return true;
            if (ns == "System.Collections.Generic" && n == "IEnumerator`1") return true;
        }
        return false;
    }

    public static ITypeDefOrRef StringType(ModuleDefinition m) => m.CorLibTypeFactory.String.ToTypeDefOrRef();
    public static ITypeDefOrRef ObjectType(ModuleDefinition m) => m.CorLibTypeFactory.Object.ToTypeDefOrRef();
    public static ITypeDefOrRef CharType(ModuleDefinition m) => m.CorLibTypeFactory.Char.ToTypeDefOrRef();

    public static SzArrayTypeSignature CharArray(ModuleDefinition m) => m.CorLibTypeFactory.Char.MakeSzArrayType();
    public static SzArrayTypeSignature ByteArray(ModuleDefinition m) => m.CorLibTypeFactory.Byte.MakeSzArrayType();

    /// <summary>System.String::get_Length() : int32 (instance).</summary>
    public static IMethodDefOrRef StringGetLength(ModuleDefinition m)
    {
        var sig = MethodSignature.CreateInstance(m.CorLibTypeFactory.Int32);
        var mr = new MemberReference(StringType(m), "get_Length", sig);
        return (IMethodDefOrRef)m.DefaultImporter.ImportMethod(mr);
    }

    /// <summary>System.String::get_Chars(int32) : char (instance).</summary>
    public static IMethodDefOrRef StringGetChars(ModuleDefinition m)
    {
        var sig = MethodSignature.CreateInstance(m.CorLibTypeFactory.Char,
            new TypeSignature[] { m.CorLibTypeFactory.Int32 });
        var mr = new MemberReference(StringType(m), "get_Chars", sig);
        return (IMethodDefOrRef)m.DefaultImporter.ImportMethod(mr);
    }

    /// <summary>System.String::.ctor(char[]) : void (instance).</summary>
    public static IMethodDefOrRef StringCtorCharArray(ModuleDefinition m)
    {
        var sig = MethodSignature.CreateInstance(m.CorLibTypeFactory.Void,
            new TypeSignature[] { CharArray(m) });
        var mr = new MemberReference(StringType(m), ".ctor", sig);
        return (IMethodDefOrRef)m.DefaultImporter.ImportMethod(mr);
    }

    /// <summary>Resolves a type without throwing when the declaring assembly is unavailable.</summary>
    public static TypeDefinition? SafeResolve(ITypeDefOrRef? t, RuntimeContext rc)
    {
        try { return t?.Resolve(rc); }
        catch { return null; }
    }

    /// <summary>Resolves a method without throwing when the declaring assembly is unavailable.</summary>
    public static MethodDefinition? SafeResolve(IMethodDefOrRef? m, RuntimeContext rc)
    {
        try { return m?.Resolve(rc); }
        catch { return null; }
    }

    /// <summary>A TypeReference into the module's own corlib (portable across Mono/CoreCLR).</summary>
    public static TypeReference CorLibType(ModuleDefinition m, string ns, string name)
        => new TypeReference(m, (IResolutionScope)m.CorLibTypeFactory.CorLibScope, ns, name);

    /// <summary>Imports a static corlib method reference (portable across Mono/CoreCLR).</summary>
    public static IMethodDefOrRef ImportStatic(ModuleDefinition m, string ns, string typeName,
        string method, TypeSignature ret, params TypeSignature[] pars)
    {
        var tr = CorLibType(m, ns, typeName);
        var sig = MethodSignature.CreateStatic(ret, pars);
        return (IMethodDefOrRef)m.DefaultImporter.ImportMethod(new MemberReference(tr, method, sig));
    }

    /// <summary>Gets (or adds) a ModuleReference for a native DLL, e.g. "kernel32.dll".</summary>
    public static ModuleReference GetNativeModule(ModuleDefinition m, string dll)
    {
        foreach (var mr in m.ModuleReferences)
            if (mr.Name?.Value == dll)
                return mr;
        var r = new ModuleReference(dll);
        m.ModuleReferences.Add(r);
        return r;
    }

    /// <summary>Creates a P/Invoke method (no body) bound to a native export.</summary>
    public static MethodDefinition CreatePInvoke(ModuleDefinition m, TypeDefinition holder, ModuleReference dll,
        string entry, MethodSignature sig, bool setLastError = false, bool unicode = false)
    {
        var method = new MethodDefinition(entry,
            MethodAttributes.Public | MethodAttributes.Static
            | MethodAttributes.PInvokeImpl | MethodAttributes.HideBySig, sig);

        var flags = ImplementationMapAttributes.CallConvWinapi;
        if (setLastError) flags |= ImplementationMapAttributes.SupportsLastError;
        if (unicode) flags |= ImplementationMapAttributes.CharSetUnicode;

        method.ImplementationMap = new ImplementationMap(dll, entry, flags);
        method.ImplAttributes |= MethodImplAttributes.PreserveSig;
        holder.Methods.Add(method);
        return method;
    }

    /// <summary>Creates a new sealed+abstract (static) top-level class to hold injected helpers.</summary>
    public static TypeDefinition CreateStaticHolder(ModuleDefinition m, string name)
    {
        var t = new TypeDefinition(
            null, name,
            TypeAttributes.Class
            | TypeAttributes.Sealed
            | TypeAttributes.Abstract
            | TypeAttributes.NotPublic
            | TypeAttributes.BeforeFieldInit,
            ObjectType(m));
        m.TopLevelTypes.Add(t);
        return t;
    }
}
