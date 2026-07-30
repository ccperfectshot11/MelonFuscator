using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Aggressive anti-debug. Injects the strongest portable native detection set (mirroring
/// the "common point" checks from the referenced anticheat) and terminates the process on
/// detection. Everything is emitted with corlib types + P/Invoke to kernel32/ntdll only, so
/// it is cross-runtime (Mono/CoreCLR) and the whole thing is wrapped in try/catch so it
/// degrades gracefully on non-Windows hosts.
///
/// Checks: Debugger.IsAttached, Debugger.IsLogging, IsDebuggerPresent,
/// CheckRemoteDebuggerPresent, NtQueryInformationProcess (ProcessDebugPort=7,
/// ProcessDebugObjectHandle=0x1E, ProcessDebugFlags=0x1F) and kernel-driver presence
/// (TitanHide / Cheat Engine DBK / ScyllaHide) via CreateFileW on the device symlink.
/// </summary>
public sealed class AntiDebugProtection : IProtection
{
    public string Name => "Anti-Debug (native)";
    public bool IsEnabled(ObfuscationOptions o) => o.AntiDebug;

    private static readonly string[] Drivers =
    {
        @"\\.\TitanHide", @"\\.\DBKProcList64", @"\\.\dbk64", @"\\.\dbk32", @"\\.\ScyllaHide"
    };

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var holder = CilHelpers.CreateStaticHolder(module, ctx.Names.Next());

        var kernel32 = CilHelpers.GetNativeModule(module, "kernel32.dll");
        var ntdll = CilHelpers.GetNativeModule(module, "ntdll.dll");

        var f = module.CorLibTypeFactory;
        var intPtr = f.IntPtr;
        var intPtrRef = f.IntPtr.MakeByReferenceType();
        var int32Ref = f.Int32.MakeByReferenceType();
        var boolRef = f.Boolean.MakeByReferenceType();

        // --- P/Invoke declarations ---
        var pIsDebuggerPresent = CilHelpers.CreatePInvoke(module, holder, kernel32, "IsDebuggerPresent",
            MethodSignature.CreateStatic(f.Boolean));
        var pGetCurrentProcess = CilHelpers.CreatePInvoke(module, holder, kernel32, "GetCurrentProcess",
            MethodSignature.CreateStatic(f.IntPtr));
        var pCheckRemote = CilHelpers.CreatePInvoke(module, holder, kernel32, "CheckRemoteDebuggerPresent",
            MethodSignature.CreateStatic(f.Boolean, new TypeSignature[] { intPtr, boolRef }), setLastError: true);
        var pNtQuery = CilHelpers.CreatePInvoke(module, holder, ntdll, "NtQueryInformationProcess",
            MethodSignature.CreateStatic(f.Int32, new TypeSignature[] { intPtr, f.Int32, intPtrRef, f.Int32, int32Ref }));
        var pCreateFile = CilHelpers.CreatePInvoke(module, holder, kernel32, "CreateFileW",
            MethodSignature.CreateStatic(f.IntPtr, new TypeSignature[] { f.String, f.UInt32, f.UInt32, intPtr, f.UInt32, f.UInt32, intPtr }),
            setLastError: true, unicode: true);
        var pCloseHandle = CilHelpers.CreatePInvoke(module, holder, kernel32, "CloseHandle",
            MethodSignature.CreateStatic(f.Boolean, new TypeSignature[] { intPtr }), setLastError: true);

        // Managed corlib references.
        var isAttached = CilHelpers.ImportStatic(module, "System.Diagnostics", "Debugger", "get_IsAttached", f.Boolean);
        var isLogging = CilHelpers.ImportStatic(module, "System.Diagnostics", "Debugger", "IsLogging", f.Boolean);
        var ptrSize = CilHelpers.ImportStatic(module, "System", "IntPtr", "get_Size", f.Int32);
        var exit = CilHelpers.ImportStatic(module, "System", "Environment", "Exit", f.Void, f.Int32);

        var driverLoaded = EmitDriverLoaded(module, holder, ctx.Names.Next(), pCreateFile, pCloseHandle);
        var detect = EmitDetect(module, holder, ctx.Names.Next(),
            isAttached, isLogging, ptrSize, pIsDebuggerPresent, pGetCurrentProcess, pCheckRemote, pNtQuery, driverLoaded);
        var guard = EmitGuard(module, holder, ctx.Names.Next(), detect, exit);

        ModuleInitializer.CallFromModuleInitializer(module, guard);
        ctx.Log.Step("injected native debugger + driver detection (7/0x1E/0x1F + CreateFileW)");
    }

    // static bool DriverLoaded(string dev)
    private static MethodDefinition EmitDriverLoaded(ModuleDefinition module, TypeDefinition holder, string name,
        MethodDefinition createFile, MethodDefinition closeHandle)
    {
        var f = module.CorLibTypeFactory;
        var m = new MethodDefinition(name,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodSignature.CreateStatic(f.Boolean, new TypeSignature[] { f.String }));
        holder.Methods.Add(m);
        var body = new CilMethodBody();
        m.CilMethodBody = body;
        var h = new CilLocalVariable(f.IntPtr);
        body.LocalVariables.Add(h);
        var n = body.Instructions;

        // h = CreateFileW(dev, 0, 0, IntPtr.Zero, OPEN_EXISTING(3), 0, IntPtr.Zero)
        n.Add(new CilInstruction(CilOpCodes.Ldarg_0));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Conv_I));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_3));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Conv_I));
        n.Add(new CilInstruction(CilOpCodes.Call, createFile));
        n.Add(new CilInstruction(CilOpCodes.Stloc, h));

        // if (h == -1) return false;
        n.Add(new CilInstruction(CilOpCodes.Ldloc, h));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_M1));
        n.Add(new CilInstruction(CilOpCodes.Conv_I));
        var retFalse = new CilInstruction(CilOpCodes.Ldc_I4_0);
        var beqFalse = new CilInstruction(CilOpCodes.Beq, new CilInstructionLabel(retFalse));
        n.Add(beqFalse);

        // CloseHandle(h); return true;
        n.Add(new CilInstruction(CilOpCodes.Ldloc, h));
        n.Add(new CilInstruction(CilOpCodes.Call, closeHandle));
        n.Add(new CilInstruction(CilOpCodes.Pop));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
        n.Add(new CilInstruction(CilOpCodes.Ret));

        n.Add(retFalse);                                  // ldc.i4.0
        n.Add(new CilInstruction(CilOpCodes.Ret));

        body.Instructions.CalculateOffsets();
        return m;
    }

    // static bool Detect()
    private static MethodDefinition EmitDetect(ModuleDefinition module, TypeDefinition holder, string name,
        IMethodDefOrRef isAttached, IMethodDefOrRef isLogging, IMethodDefOrRef ptrSize,
        MethodDefinition isDebuggerPresent, MethodDefinition getCurrentProcess, MethodDefinition checkRemote,
        MethodDefinition ntQuery, MethodDefinition driverLoaded)
    {
        var f = module.CorLibTypeFactory;
        var m = new MethodDefinition(name,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodSignature.CreateStatic(f.Boolean));
        holder.Methods.Add(m);
        var body = new CilMethodBody();
        m.CilMethodBody = body;

        var h = new CilLocalVariable(f.IntPtr);
        var remote = new CilLocalVariable(f.Boolean);
        var size = new CilLocalVariable(f.Int32);
        var rl = new CilLocalVariable(f.Int32);
        var port = new CilLocalVariable(f.IntPtr);
        var obj = new CilLocalVariable(f.IntPtr);
        var flags = new CilLocalVariable(f.IntPtr);
        foreach (var lv in new[] { h, remote, size, rl, port, obj, flags })
            body.LocalVariables.Add(lv);

        var n = body.Instructions;
        var retTrue = new CilInstruction(CilOpCodes.Ldc_I4_1);

        // Debugger.IsAttached / IsLogging / IsDebuggerPresent
        n.Add(new CilInstruction(CilOpCodes.Call, isAttached));
        n.Add(new CilInstruction(CilOpCodes.Brtrue, new CilInstructionLabel(retTrue)));
        n.Add(new CilInstruction(CilOpCodes.Call, isLogging));
        n.Add(new CilInstruction(CilOpCodes.Brtrue, new CilInstructionLabel(retTrue)));
        n.Add(new CilInstruction(CilOpCodes.Call, isDebuggerPresent));
        n.Add(new CilInstruction(CilOpCodes.Brtrue, new CilInstructionLabel(retTrue)));

        // h = GetCurrentProcess()
        n.Add(new CilInstruction(CilOpCodes.Call, getCurrentProcess));
        n.Add(new CilInstruction(CilOpCodes.Stloc, h));

        // remote = false; CheckRemoteDebuggerPresent(h, ref remote); if (remote) true;
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Stloc, remote));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, h));
        n.Add(new CilInstruction(CilOpCodes.Ldloca, remote));
        n.Add(new CilInstruction(CilOpCodes.Call, checkRemote));
        n.Add(new CilInstruction(CilOpCodes.Pop));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, remote));
        n.Add(new CilInstruction(CilOpCodes.Brtrue, new CilInstructionLabel(retTrue)));

        // size = IntPtr.Size; rl = 0;
        n.Add(new CilInstruction(CilOpCodes.Call, ptrSize));
        n.Add(new CilInstruction(CilOpCodes.Stloc, size));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Stloc, rl));

        // ProcessDebugPort (7): status==0 && port!=0 -> debugger
        var skip1 = new CilInstruction(CilOpCodes.Ldc_I4_0);   // placeholder start of next block (obj=0)
        EmitNtCheckNonZero(n, ntQuery, h, 7, port, size, rl, retTrue, skip1);
        // ProcessDebugObjectHandle (0x1E): status==0 && obj!=0 -> debugger
        n.Add(skip1);                                          // obj = 0 (ldc.i4.0)
        n.Add(new CilInstruction(CilOpCodes.Conv_I));
        n.Add(new CilInstruction(CilOpCodes.Stloc, obj));
        var skip2 = new CilInstruction(CilOpCodes.Ldc_I4_1);   // start of flags block (flags=1)
        EmitNtQuery(n, ntQuery, h, 0x1E, obj, size, rl);
        n.Add(new CilInstruction(CilOpCodes.Brtrue, new CilInstructionLabel(skip2)));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, obj));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Conv_I));
        n.Add(new CilInstruction(CilOpCodes.Bne_Un, new CilInstructionLabel(retTrue)));

        // ProcessDebugFlags (0x1F): status==0 && flags==0 -> debugger
        n.Add(skip2);                                          // flags = 1 (ldc.i4.1)
        n.Add(new CilInstruction(CilOpCodes.Conv_I));
        n.Add(new CilInstruction(CilOpCodes.Stloc, flags));
        var driversStart = new CilInstruction(CilOpCodes.Ldstr, Drivers[0]);
        EmitNtQuery(n, ntQuery, h, 0x1F, flags, size, rl);
        n.Add(new CilInstruction(CilOpCodes.Brtrue, new CilInstructionLabel(driversStart)));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, flags));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Conv_I));
        n.Add(new CilInstruction(CilOpCodes.Beq, new CilInstructionLabel(retTrue)));

        // drivers
        for (int i = 0; i < Drivers.Length; i++)
        {
            var ins = i == 0 ? driversStart : new CilInstruction(CilOpCodes.Ldstr, Drivers[i]);
            n.Add(ins);
            n.Add(new CilInstruction(CilOpCodes.Call, driverLoaded));
            n.Add(new CilInstruction(CilOpCodes.Brtrue, new CilInstructionLabel(retTrue)));
        }

        // return false;
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Ret));

        // return true;
        n.Add(retTrue);
        n.Add(new CilInstruction(CilOpCodes.Ret));

        body.Instructions.CalculateOffsets();
        return m;
    }

    // Emits: NtQuery(h, cls, ref slot, size, ref rl)  (leaves the int status on the stack)
    private static void EmitNtQuery(CilInstructionCollection n, MethodDefinition ntQuery,
        CilLocalVariable h, int cls, CilLocalVariable slot, CilLocalVariable size, CilLocalVariable rl)
    {
        n.Add(new CilInstruction(CilOpCodes.Ldloc, h));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, cls));
        n.Add(new CilInstruction(CilOpCodes.Ldloca, slot));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, size));
        n.Add(new CilInstruction(CilOpCodes.Ldloca, rl));
        n.Add(new CilInstruction(CilOpCodes.Call, ntQuery));
    }

    // ProcessDebugPort-style: slot = 0; status = NtQuery(...); if (status==0 && slot!=0) -> retTrue; else fall to skip.
    private static void EmitNtCheckNonZero(CilInstructionCollection n, MethodDefinition ntQuery,
        CilLocalVariable h, int cls, CilLocalVariable slot, CilLocalVariable size, CilLocalVariable rl,
        CilInstruction retTrue, CilInstruction skip)
    {
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Conv_I));
        n.Add(new CilInstruction(CilOpCodes.Stloc, slot));
        EmitNtQuery(n, ntQuery, h, cls, slot, size, rl);
        n.Add(new CilInstruction(CilOpCodes.Brtrue, new CilInstructionLabel(skip))); // status != 0 -> skip
        n.Add(new CilInstruction(CilOpCodes.Ldloc, slot));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Conv_I));
        n.Add(new CilInstruction(CilOpCodes.Bne_Un, new CilInstructionLabel(retTrue)));
    }

    // static void Guard() { try { if (Detect()) Environment.Exit(0); } catch { } }
    private static MethodDefinition EmitGuard(ModuleDefinition module, TypeDefinition holder, string name,
        MethodDefinition detect, IMethodDefOrRef exit)
    {
        var f = module.CorLibTypeFactory;
        var m = new MethodDefinition(name,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodSignature.CreateStatic(f.Void));
        holder.Methods.Add(m);
        var body = new CilMethodBody();
        m.CilMethodBody = body;
        var n = body.Instructions;

        var end = new CilInstruction(CilOpCodes.Ret);
        var tryStart = new CilInstruction(CilOpCodes.Call, detect);
        var afterExit = new CilInstruction(CilOpCodes.Leave, new CilInstructionLabel(end));
        var handlerStart = new CilInstruction(CilOpCodes.Pop);

        n.Add(tryStart);
        n.Add(new CilInstruction(CilOpCodes.Brfalse, new CilInstructionLabel(afterExit)));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Call, exit));
        n.Add(afterExit);                     // leave END
        n.Add(handlerStart);                  // pop
        n.Add(new CilInstruction(CilOpCodes.Leave, new CilInstructionLabel(end)));
        n.Add(end);                           // ret

        var excType = CilHelpers.CorLibType(module, "System", "Exception");
        body.ExceptionHandlers.Add(new CilExceptionHandler
        {
            HandlerType = CilExceptionHandlerType.Exception,
            TryStart = new CilInstructionLabel(tryStart),
            TryEnd = new CilInstructionLabel(handlerStart),
            HandlerStart = new CilInstructionLabel(handlerStart),
            HandlerEnd = new CilInstructionLabel(end),
            ExceptionType = excType,
        });

        body.Instructions.CalculateOffsets();
        return m;
    }
}
