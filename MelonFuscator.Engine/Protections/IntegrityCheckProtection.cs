using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// MelonLoader-safe anti-tamper. Embeds the final type count and verifies it at runtime via
/// reflection. Automated deobfuscators (de4dot, ...) strip the injected proxy/decoy/junk types,
/// which lowers the count and trips this check.
///
/// It is deliberately FAIL-OPEN: the whole check is wrapped in try/catch, so if reflection
/// throws (e.g. Assembly.GetTypes() on an IL2CPP assembly whose types aren't fully loadable)
/// it simply does nothing. That guarantees zero false positives - it never breaks a legitimate
/// mod, it only reacts when it can positively confirm the type count was reduced.
///
/// Runs LAST so it sees the final type count.
/// </summary>
public sealed class IntegrityCheckProtection : IProtection
{
    public string Name => "Integrity Check (anti-tamper)";
    public bool IsEnabled(ObfuscationOptions o) => o.AntiTamper;

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var f = module.CorLibTypeFactory;

        // Reflection's Assembly.GetTypes() returns every type except <Module>; AsmResolver's
        // GetAllTypes() includes it. We add exactly one holder type below, so at runtime the
        // reflected count equals the current GetAllTypes() count.
        int expected = module.GetAllTypes().Count();

        var holder = CilHelpers.CreateStaticHolder(module, ctx.Names.Next());

        var asmType = CilHelpers.CorLibType(module, "System.Reflection", "Assembly");
        var getExecAsm = (IMethodDefOrRef)module.DefaultImporter.ImportMethod(
            new MemberReference(asmType, "GetExecutingAssembly",
                MethodSignature.CreateStatic(asmType.ToTypeSignature(false))));
        var typeArray = CilHelpers.CorLibType(module, "System", "Type").ToTypeSignature(false).MakeSzArrayType();
        var getTypes = (IMethodDefOrRef)module.DefaultImporter.ImportMethod(
            new MemberReference(asmType, "GetTypes", MethodSignature.CreateInstance(typeArray)));
        var exit = CilHelpers.ImportStatic(module, "System", "Environment", "Exit", f.Void, f.Int32);

        var check = new MethodDefinition(ctx.Names.Next(),
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodSignature.CreateStatic(f.Void));
        holder.Methods.Add(check);
        var body = new CilMethodBody();
        check.CilMethodBody = body;
        var n = body.Instructions;

        var end = new CilInstruction(CilOpCodes.Ret);
        var tryStart = new CilInstruction(CilOpCodes.Call, getExecAsm);
        var handlerStart = new CilInstruction(CilOpCodes.Pop);
        var afterExit = new CilInstruction(CilOpCodes.Leave, new CilInstructionLabel(end));

        n.Add(tryStart);
        n.Add(new CilInstruction(CilOpCodes.Callvirt, getTypes));
        n.Add(new CilInstruction(CilOpCodes.Ldlen));
        n.Add(new CilInstruction(CilOpCodes.Conv_I4));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, expected));
        // Trigger ONLY when the count dropped below expected (types stripped by a deobfuscator).
        // A higher count (e.g. Il2CppInterop adding types) or a thrown GetTypes() never triggers.
        n.Add(new CilInstruction(CilOpCodes.Bge, new CilInstructionLabel(afterExit)));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Call, exit));
        n.Add(afterExit);
        n.Add(handlerStart);                              // pop the exception
        n.Add(new CilInstruction(CilOpCodes.Leave, new CilInstructionLabel(end)));
        n.Add(end);

        body.ExceptionHandlers.Add(new CilExceptionHandler
        {
            HandlerType = CilExceptionHandlerType.Exception,
            TryStart = new CilInstructionLabel(tryStart),
            TryEnd = new CilInstructionLabel(handlerStart),
            HandlerStart = new CilInstructionLabel(handlerStart),
            HandlerEnd = new CilInstructionLabel(end),
            ExceptionType = CilHelpers.CorLibType(module, "System", "Exception"),
        });

        body.Instructions.CalculateOffsets();
        ModuleInitializer.CallFromModuleInitializer(module, check);
        ctx.Log.Step($"embedded reflection integrity check (expected type count {expected})");
    }
}
