using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Anti-decompiler / anti-dnSpy / anti-ILSpy / anti-de4dot layer.
///  - Adds SuppressIldasmAttribute so naive ILDASM refuses to disassemble.
///  - Injects many decoy string->string methods that look exactly like string decryptors,
///    poisoning de4dot's automatic string-decryptor detection: it can no longer tell which
///    of the dozens of candidates is the real one, so its static string cleanup fails.
/// All of this keeps the metadata fully valid, so MelonLoader's verifier still passes.
/// </summary>
public sealed class AntiDecompilerProtection : IProtection
{
    public string Name => "Anti-Decompiler (dnSpy/ILSpy/de4dot)";
    public bool IsEnabled(ObfuscationOptions o) => o.AntiDecompiler;

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;

        AddSuppressIldasm(module);

        // Inject decoy decryptor-shaped methods.
        int decoys = 6 + ctx.Rng.Next(6);
        var holder = CilHelpers.CreateStaticHolder(module, ctx.Names.Next());
        for (int i = 0; i < decoys; i++)
            EmitDecoyDecryptor(module, holder, ctx);

        ctx.Log.Step($"added SuppressIldasm + {decoys} decoy string decryptors");
    }

    private static void AddSuppressIldasm(ModuleDefinition module)
    {
        if (module.Assembly == null)
            return;

        var ctorSig = MethodSignature.CreateInstance(module.CorLibTypeFactory.Void);
        var tr = CilHelpers.CorLibType(module, "System.Runtime.CompilerServices", "SuppressIldasmAttribute");
        var ctor = (ICustomAttributeType)module.DefaultImporter.ImportMethod(new MemberReference(tr, ".ctor", ctorSig));
        module.Assembly.CustomAttributes.Add(new CustomAttribute(ctor));
    }

    // A method with the exact shape de4dot looks for (string in, string out) but which just
    // returns a scrambled copy of the input. Harmless if ever called; it is never referenced.
    private static void EmitDecoyDecryptor(ModuleDefinition module, TypeDefinition holder, ObfuscationContext ctx)
    {
        var sig = MethodSignature.CreateStatic(module.CorLibTypeFactory.String,
            new TypeSignature[] { module.CorLibTypeFactory.String });
        var m = new MethodDefinition(ctx.Names.Next(),
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, sig);
        holder.Methods.Add(m);

        var body = new CilMethodBody();
        m.CilMethodBody = body;

        var lenLocal = new CilLocalVariable(module.CorLibTypeFactory.Int32);
        var bufLocal = new CilLocalVariable(CilHelpers.CharArray(module));
        var iLocal = new CilLocalVariable(module.CorLibTypeFactory.Int32);
        body.LocalVariables.Add(lenLocal);
        body.LocalVariables.Add(bufLocal);
        body.LocalVariables.Add(iLocal);

        var getLength = CilHelpers.StringGetLength(module);
        var getChars = CilHelpers.StringGetChars(module);
        var strCtor = CilHelpers.StringCtorCharArray(module);
        var charType = CilHelpers.CharType(module);
        int fakeKey = ctx.Rng.Next();

        var n = body.Instructions;
        n.Add(new CilInstruction(CilOpCodes.Ldarg_0));
        n.Add(new CilInstruction(CilOpCodes.Callvirt, getLength));
        n.Add(new CilInstruction(CilOpCodes.Stloc, lenLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, lenLocal));
        n.Add(new CilInstruction(CilOpCodes.Newarr, charType));
        n.Add(new CilInstruction(CilOpCodes.Stloc, bufLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Stloc, iLocal));

        var cond = new CilInstruction(CilOpCodes.Ldloc, iLocal);
        n.Add(cond);
        n.Add(new CilInstruction(CilOpCodes.Ldloc, lenLocal));
        var brExit = new CilInstruction(CilOpCodes.Bge, null!);
        n.Add(brExit);

        n.Add(new CilInstruction(CilOpCodes.Ldloc, bufLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, iLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldarg_0));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, iLocal));
        n.Add(new CilInstruction(CilOpCodes.Callvirt, getChars));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, fakeKey));
        n.Add(new CilInstruction(CilOpCodes.Xor));
        n.Add(new CilInstruction(CilOpCodes.Conv_U2));
        n.Add(new CilInstruction(CilOpCodes.Stelem_I2));

        n.Add(new CilInstruction(CilOpCodes.Ldloc, iLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
        n.Add(new CilInstruction(CilOpCodes.Add));
        n.Add(new CilInstruction(CilOpCodes.Stloc, iLocal));
        var brBack = new CilInstruction(CilOpCodes.Br, null!);
        n.Add(brBack);

        var exit = new CilInstruction(CilOpCodes.Ldloc, bufLocal);
        n.Add(exit);
        n.Add(new CilInstruction(CilOpCodes.Newobj, strCtor));
        n.Add(new CilInstruction(CilOpCodes.Ret));

        brExit.Operand = new CilInstructionLabel(exit);
        brBack.Operand = new CilInstructionLabel(cond);
        body.Instructions.CalculateOffsets();
    }
}
