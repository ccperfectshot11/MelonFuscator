using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

// AsmResolver 6.x: MethodSignature.Create* takes an array/IEnumerable, and CilMethodBody
// has a parameterless ctor whose Owner is set on assignment to method.CilMethodBody.

/// <summary>
/// Encrypts every string literal (ldstr) in the module. A decrypt method is generated
/// directly in the target module using only corlib types, so it runs on both Unity Mono
/// and IL2CPP/CoreCLR. The keystream is pure arithmetic (no external calls) and identical
/// between the C# encryptor here and the emitted IL decryptor, which makes it symmetric.
/// </summary>
public sealed class StringEncryptionProtection : IProtection
{
    public string Name => "String Encryption";
    public bool IsEnabled(ObfuscationOptions o) => o.EncryptStrings;

    // Golden-ratio odd constant used in the keystream mix.
    private const int A = unchecked((int)0x9E3779B1);

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        int key = ctx.Rng.Next(int.MinValue, int.MaxValue);

        var holder = CilHelpers.CreateStaticHolder(module, ctx.Names.Next());
        var decrypt = EmitDecryptMethod(module, holder, key);

        int count = 0;
        foreach (var type in module.GetAllTypes())
        {
            foreach (var method in type.Methods)
            {
                var body = method.CilMethodBody;
                if (body == null) continue;
                if (method == decrypt) continue;

                var instrs = body.Instructions;
                for (int i = 0; i < instrs.Count; i++)
                {
                    var ins = instrs[i];
                    if (ins.OpCode.Code != CilCode.Ldstr) continue;
                    if (ins.Operand is not string s) continue;

                    var cipher = Encrypt(s, key);
                    ins.Operand = cipher;                        // keep ldstr, swap the literal
                    instrs.Insert(i + 1, new CilInstruction(CilOpCodes.Call, decrypt));
                    i++;                                         // skip over the inserted call
                    count++;
                }
            }
        }

        ctx.Log.Step($"encrypted {count} string literal(s)");
    }

    // Encrypts on UTF-8 bytes and stores the cipher as a string whose code units are all
    // in 0..255. That avoids lone UTF-16 surrogates, which do not survive the #US heap
    // round-trip and would corrupt the text. Symmetric with the emitted IL decryptor.
    private static string Encrypt(string s, int key)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(s);
        var arr = new char[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
        {
            int k = ((i * A) + key) ^ (i << 4);
            int ks = k & 0xFF;
            arr[i] = (char)((bytes[i] ^ ks) & 0xFF);
        }
        return new string(arr);
    }

    // Generates: static string Decrypt(string cipher)
    //   byte[] buf = new byte[cipher.Length];
    //   for (i) buf[i] = (byte)(cipher[i] ^ ((i*A + key) ^ (i<<4)) & 0xFF);
    //   return Encoding.UTF8.GetString(buf);
    private static MethodDefinition EmitDecryptMethod(ModuleDefinition module, TypeDefinition holder, int key)
    {
        var sig = MethodSignature.CreateStatic(module.CorLibTypeFactory.String,
            new TypeSignature[] { module.CorLibTypeFactory.String });
        var method = new MethodDefinition("Decrypt",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, sig);
        holder.Methods.Add(method);

        var body = new CilMethodBody();
        method.CilMethodBody = body;

        var lenLocal = new CilLocalVariable(module.CorLibTypeFactory.Int32);
        var bufLocal = new CilLocalVariable(CilHelpers.ByteArray(module));
        var iLocal = new CilLocalVariable(module.CorLibTypeFactory.Int32);
        body.LocalVariables.Add(lenLocal);
        body.LocalVariables.Add(bufLocal);
        body.LocalVariables.Add(iLocal);

        var getLength = CilHelpers.StringGetLength(module);
        var getChars = CilHelpers.StringGetChars(module);
        var byteType = module.CorLibTypeFactory.Byte.ToTypeDefOrRef();

        // System.Text.Encoding.UTF8 (static getter) + Encoding.GetString(byte[]) (instance).
        var encodingType = CilHelpers.CorLibType(module, "System.Text", "Encoding");
        var getUtf8 = (IMethodDefOrRef)module.DefaultImporter.ImportMethod(
            new MemberReference(encodingType, "get_UTF8",
                MethodSignature.CreateStatic(encodingType.ToTypeSignature(false))));
        var getString = (IMethodDefOrRef)module.DefaultImporter.ImportMethod(
            new MemberReference(encodingType, "GetString",
                MethodSignature.CreateInstance(module.CorLibTypeFactory.String,
                    new TypeSignature[] { CilHelpers.ByteArray(module) })));

        var n = body.Instructions;

        // len = cipher.Length; buf = new byte[len]; i = 0;
        n.Add(new CilInstruction(CilOpCodes.Ldarg_0));
        n.Add(new CilInstruction(CilOpCodes.Callvirt, getLength));
        n.Add(new CilInstruction(CilOpCodes.Stloc, lenLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, lenLocal));
        n.Add(new CilInstruction(CilOpCodes.Newarr, byteType));
        n.Add(new CilInstruction(CilOpCodes.Stloc, bufLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
        n.Add(new CilInstruction(CilOpCodes.Stloc, iLocal));

        var cond = new CilInstruction(CilOpCodes.Ldloc, iLocal);
        n.Add(cond);
        n.Add(new CilInstruction(CilOpCodes.Ldloc, lenLocal));
        var brExit = new CilInstruction(CilOpCodes.Bge, null!);
        n.Add(brExit);

        // buf[i] = (byte)(cipher[i] ^ (((i*A + key) ^ (i<<4)) & 0xFF))
        n.Add(new CilInstruction(CilOpCodes.Ldloc, bufLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, iLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldarg_0));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, iLocal));
        n.Add(new CilInstruction(CilOpCodes.Callvirt, getChars));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, iLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, A));
        n.Add(new CilInstruction(CilOpCodes.Mul));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, key));
        n.Add(new CilInstruction(CilOpCodes.Add));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, iLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_4));
        n.Add(new CilInstruction(CilOpCodes.Shl));
        n.Add(new CilInstruction(CilOpCodes.Xor));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, 0xFF));
        n.Add(new CilInstruction(CilOpCodes.And));
        n.Add(new CilInstruction(CilOpCodes.Xor));
        n.Add(new CilInstruction(CilOpCodes.Conv_U1));
        n.Add(new CilInstruction(CilOpCodes.Stelem_I1));

        // i++
        n.Add(new CilInstruction(CilOpCodes.Ldloc, iLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
        n.Add(new CilInstruction(CilOpCodes.Add));
        n.Add(new CilInstruction(CilOpCodes.Stloc, iLocal));
        var brBack = new CilInstruction(CilOpCodes.Br, null!);
        n.Add(brBack);

        // exit: return Encoding.UTF8.GetString(buf)
        var exit = new CilInstruction(CilOpCodes.Call, getUtf8);
        n.Add(exit);
        n.Add(new CilInstruction(CilOpCodes.Ldloc, bufLocal));
        n.Add(new CilInstruction(CilOpCodes.Callvirt, getString));
        n.Add(new CilInstruction(CilOpCodes.Ret));

        brExit.Operand = new CilInstructionLabel(exit);
        brBack.Operand = new CilInstructionLabel(cond);

        body.Instructions.CalculateOffsets();
        return method;
    }
}
