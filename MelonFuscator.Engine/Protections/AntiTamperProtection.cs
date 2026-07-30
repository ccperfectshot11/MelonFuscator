using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Anti-tamper / anti-instrumentation. Detects CLR profilers and instrumentation hooks
/// (used by many dynamic-analysis and unpacking tools) via their environment variables
/// and terminates if present. Verifier-safe: it only adds valid IL and a plaintext string.
/// </summary>
public sealed class AntiTamperProtection : IProtection
{
    public string Name => "Anti-Tamper";
    public bool IsEnabled(ObfuscationOptions o) => o.AntiTamper;

    private static readonly string[] ProfilerVars =
    {
        "COR_ENABLE_PROFILING", "COR_PROFILER",
        "CORECLR_ENABLE_PROFILING", "CORECLR_PROFILER",
    };

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var holder = CilHelpers.CreateStaticHolder(module, ctx.Names.Next());
        var check = EmitCheck(module, holder, ctx.Names.Next());
        ModuleInitializer.CallFromModuleInitializer(module, check);
        ctx.Log.Step("injected profiler/instrumentation detection into the module initializer");
    }

    private static MethodDefinition EmitCheck(ModuleDefinition module, TypeDefinition holder, string name)
    {
        var sig = MethodSignature.CreateStatic(module.CorLibTypeFactory.Void);
        var m = new MethodDefinition(name,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, sig);
        holder.Methods.Add(m);

        var getEnv = CilHelpers.ImportStatic(module, "System", "Environment",
            "GetEnvironmentVariable", module.CorLibTypeFactory.String, module.CorLibTypeFactory.String);
        var exit = CilHelpers.ImportStatic(module, "System", "Environment",
            "Exit", module.CorLibTypeFactory.Void, module.CorLibTypeFactory.Int32);

        var body = new CilMethodBody();
        m.CilMethodBody = body;
        var n = body.Instructions;

        var exitLabel = new CilInstruction(CilOpCodes.Ldc_I4_0);
        var ret = new CilInstruction(CilOpCodes.Ret);

        foreach (var v in ProfilerVars)
        {
            n.Add(new CilInstruction(CilOpCodes.Ldstr, v));
            n.Add(new CilInstruction(CilOpCodes.Call, getEnv));
            var brToExit = new CilInstruction(CilOpCodes.Brtrue, new CilInstructionLabel(exitLabel));
            n.Add(brToExit);
        }

        n.Add(new CilInstruction(CilOpCodes.Br, new CilInstructionLabel(ret)));

        // exit block
        n.Add(exitLabel);                                    // ldc.i4.0
        n.Add(new CilInstruction(CilOpCodes.Call, exit));
        n.Add(ret);

        body.Instructions.CalculateOffsets();
        return m;
    }
}
