using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace MelonFuscator.Engine;

/// <summary>
/// A per-build random reversible byte cipher (inspired by ConfuserEx's DynCipher). At build
/// time the engine generates a fresh random op-sequence, so every obfuscated assembly has a
/// different decryptor - a generic automated deobfuscator cannot hard-code the algorithm.
///
/// Each byte is transformed by: x ^= keystream(i); then a random chain of XOR/ADD ops. The
/// emitted IL decryptor applies the inverse chain in reverse, then removes the keystream.
/// Uses only integer arithmetic, so it is fully portable across Mono and CoreCLR/IL2CPP.
/// </summary>
public sealed class ByteCipher
{
    private enum OpKind { Xor, Add }
    private readonly record struct Op(OpKind Kind, int Operand);

    private readonly Op[] _ops;
    public int Key { get; }
    private const int A = unchecked((int)0x9E3779B1);

    // Full-width 32-bit keys for the numeric-constant transform (per build).
    private readonly int _ik1, _ik2, _ik3;

    public ByteCipher(Random rng)
    {
        Key = rng.Next(int.MinValue, int.MaxValue);
        int count = 3 + rng.Next(4);           // 3..6 ops
        _ops = new Op[count];
        for (int i = 0; i < count; i++)
        {
            var kind = rng.Next(2) == 0 ? OpKind.Xor : OpKind.Add;
            _ops[i] = new Op(kind, rng.Next(1, 256));
        }
        _ik1 = rng.Next(int.MinValue, int.MaxValue);
        _ik2 = rng.Next(int.MinValue, int.MaxValue);
        _ik3 = rng.Next(int.MinValue, int.MaxValue);
    }

    // Reversible 32-bit transform for numeric constants: enc = ((v ^ k1) + k2) ^ k3.
    public int EncryptInt32(int v) => unchecked(((v ^ _ik1) + _ik2) ^ _ik3);

    /// <summary>With the encrypted int on the stack, leaves the original int on the stack.</summary>
    public void EmitDecryptInt32(CilInstructionCollection n)
    {
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, _ik3));
        n.Add(new CilInstruction(CilOpCodes.Xor));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, _ik2));
        n.Add(new CilInstruction(CilOpCodes.Sub));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, _ik1));
        n.Add(new CilInstruction(CilOpCodes.Xor));
    }

    // Keystream byte for position i (pure arithmetic, no external calls).
    private int Keystream(int i) => ((i * A) + Key) ^ (i << 4);

    /// <summary>Encrypt one plaintext byte at position i (matches the emitted IL decryptor).</summary>
    public int EncryptByte(int plain, int i)
    {
        int x = plain ^ (Keystream(i) & 0xFF);
        foreach (var op in _ops)
            x = op.Kind == OpKind.Xor ? x ^ op.Operand : x + op.Operand;
        return x & 0xFF;
    }

    /// <summary>
    /// Emits IL that, with the cipher byte already on the stack and index local available,
    /// leaves the decrypted plaintext byte (as int) on the stack. Caller then does conv.u1/stelem.
    /// </summary>
    public void EmitDecryptByte(CilInstructionCollection n, CilLocalVariable iLocal)
    {
        // Undo the op chain in reverse.
        for (int k = _ops.Length - 1; k >= 0; k--)
        {
            var op = _ops[k];
            n.Add(new CilInstruction(CilOpCodes.Ldc_I4, op.Operand));
            n.Add(new CilInstruction(op.Kind == OpKind.Xor ? CilOpCodes.Xor : CilOpCodes.Sub));
        }
        // Remove the keystream: x ^= (keystream(i) & 0xFF).
        n.Add(new CilInstruction(CilOpCodes.Ldloc, iLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, A));
        n.Add(new CilInstruction(CilOpCodes.Mul));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, Key));
        n.Add(new CilInstruction(CilOpCodes.Add));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, iLocal));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_4));
        n.Add(new CilInstruction(CilOpCodes.Shl));
        n.Add(new CilInstruction(CilOpCodes.Xor));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4, 0xFF));
        n.Add(new CilInstruction(CilOpCodes.And));
        n.Add(new CilInstruction(CilOpCodes.Xor));
    }
}
