using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Mixed Boolean-Arithmetic (MBA) mutation. Every 32-bit integer add / sub / and / or / xor
/// is rewritten into an algebraically identical but far noisier expression, e.g.
/// <c>a + b</c> becomes <c>(a ^ b) + 2*(a &amp; b)</c>. The value is bit-for-bit the same at
/// runtime (all operations are unchecked two's-complement int32), so the mod behaves exactly
/// as before - but a decompiler prints tangled arithmetic and pattern-based cleaners such as
/// de4dot no longer recognise the original operation.
///
/// Correctness relies on <see cref="StackTyper"/>: only operations whose operands are
/// provably int32 are touched. Anything the analyzer is unsure about is left alone, so we can
/// never corrupt a long/float/pointer computation. Each eligible site randomly picks one of
/// several equivalent identities, so no two builds share a fixed signature.
/// </summary>
public sealed class MutationProtection : IProtection
{
    public string Name => "MBA Mutation";
    public bool IsEnabled(ObfuscationOptions o) => o.Mutate;

    private enum Kind { Add, Sub, And, Or, Xor }

    public void Execute(ObfuscationContext ctx)
    {
        var module = ctx.Module;
        var methods = module.GetAllTypes()
            .SelectMany(t => t.Methods)
            .Where(m => m.CilMethodBody is { } b && b.Instructions.Count > 0)
            .ToList();

        int mutated = 0, touchedMethods = 0;
        foreach (var method in methods)
        {
            var body = method.CilMethodBody!;
            var instrs = body.Instructions;

            var types = StackTyper.Compute(method);
            if (types == null) continue;   // could not prove types safely -> skip this method

            // Collect eligible sites first (instruction reference + kind), using the pre-mutation
            // type snapshot. We keep instruction references, not indices, so later in-place edits
            // do not invalidate the plan.
            var plan = new List<(CilInstruction ins, Kind kind)>();
            for (int i = 0; i < instrs.Count; i++)
            {
                if (!TryKind(instrs[i].OpCode.Code, out var kind)) continue;
                var st = types[i];
                if (st == null || st.Count < 2) continue;
                if (!StackTyper.IsInt32(st[^1]) || !StackTyper.IsInt32(st[^2])) continue;   // both operands int32
                plan.Add((instrs[i], kind));
            }
            if (plan.Count == 0) continue;

            // Two scratch int32 locals, reused by every site in this method (each site stores
            // then immediately consumes them, so sharing is safe even inside loops).
            var la = new CilLocalVariable(module.CorLibTypeFactory.Int32);
            var lb = new CilLocalVariable(module.CorLibTypeFactory.Int32);
            body.LocalVariables.Add(la);
            body.LocalVariables.Add(lb);

            foreach (var (ins, kind) in plan)
            {
                int idx = instrs.IndexOf(ins);
                if (idx < 0) continue;

                // Turn the original op into the first store (preserves this instruction's identity,
                // so any branch/exception-handler label pointing at it still lands on our sequence).
                ins.OpCode = CilOpCodes.Stloc;
                ins.Operand = lb;

                var tail = new List<CilInstruction> { new(CilOpCodes.Stloc, la) };
                EmitExpression(tail, kind, la, lb, ctx.Rng);
                instrs.InsertRange(idx + 1, tail);
                mutated++;
            }

            instrs.CalculateOffsets();
            touchedMethods++;
        }

        ctx.Log.Step($"rewrote {mutated} arithmetic op(s) as MBA across {touchedMethods} method(s)");
    }

    private static bool TryKind(CilCode code, out Kind kind)
    {
        switch (code)
        {
            case CilCode.Add: kind = Kind.Add; return true;
            case CilCode.Sub: kind = Kind.Sub; return true;
            case CilCode.And: kind = Kind.And; return true;
            case CilCode.Or:  kind = Kind.Or;  return true;
            case CilCode.Xor: kind = Kind.Xor; return true;
            default: kind = default; return false;
        }
    }

    // With b already stored in lb and 'stloc la' about to store a (added by the caller as the
    // first tail instruction), append IL that leaves the identical result on the stack.
    private static void EmitExpression(List<CilInstruction> n, Kind kind, CilLocalVariable la, CilLocalVariable lb, Random rng)
    {
        switch (kind)
        {
            case Kind.Sub:
                // a - b == a + (-b): negate b in place, then fall through to an Add identity.
                n.Add(new CilInstruction(CilOpCodes.Ldloc, lb));
                n.Add(new CilInstruction(CilOpCodes.Neg));
                n.Add(new CilInstruction(CilOpCodes.Stloc, lb));
                EmitAdd(n, la, lb, rng);
                break;
            case Kind.Add:
                EmitAdd(n, la, lb, rng);
                break;
            case Kind.Xor:
                if (rng.Next(2) == 0)
                {
                    // (a | b) - (a & b)
                    Or(n, la, lb); And(n, la, lb); n.Add(new CilInstruction(CilOpCodes.Sub));
                }
                else
                {
                    // (a + b) - 2*(a & b)
                    n.Add(new CilInstruction(CilOpCodes.Ldloc, la));
                    n.Add(new CilInstruction(CilOpCodes.Ldloc, lb));
                    n.Add(new CilInstruction(CilOpCodes.Add));
                    And(n, la, lb);
                    n.Add(new CilInstruction(CilOpCodes.Ldc_I4_2));
                    n.Add(new CilInstruction(CilOpCodes.Mul));
                    n.Add(new CilInstruction(CilOpCodes.Sub));
                }
                break;
            case Kind.Or:
                // (a & b) + (a ^ b)
                And(n, la, lb); Xor(n, la, lb); n.Add(new CilInstruction(CilOpCodes.Add));
                break;
            case Kind.And:
                // (a | b) - (a ^ b)
                Or(n, la, lb); Xor(n, la, lb); n.Add(new CilInstruction(CilOpCodes.Sub));
                break;
        }
    }

    private static void EmitAdd(List<CilInstruction> n, CilLocalVariable la, CilLocalVariable lb, Random rng)
    {
        if (rng.Next(2) == 0)
        {
            // (a ^ b) + 2*(a & b)
            Xor(n, la, lb);
            And(n, la, lb);
            n.Add(new CilInstruction(CilOpCodes.Ldc_I4_2));
            n.Add(new CilInstruction(CilOpCodes.Mul));
            n.Add(new CilInstruction(CilOpCodes.Add));
        }
        else
        {
            // (a | b) + (a & b)
            Or(n, la, lb);
            And(n, la, lb);
            n.Add(new CilInstruction(CilOpCodes.Add));
        }
    }

    private static void Or(List<CilInstruction> n, CilLocalVariable la, CilLocalVariable lb)
    {
        n.Add(new CilInstruction(CilOpCodes.Ldloc, la));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, lb));
        n.Add(new CilInstruction(CilOpCodes.Or));
    }

    private static void And(List<CilInstruction> n, CilLocalVariable la, CilLocalVariable lb)
    {
        n.Add(new CilInstruction(CilOpCodes.Ldloc, la));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, lb));
        n.Add(new CilInstruction(CilOpCodes.And));
    }

    private static void Xor(List<CilInstruction> n, CilLocalVariable la, CilLocalVariable lb)
    {
        n.Add(new CilInstruction(CilOpCodes.Ldloc, la));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, lb));
        n.Add(new CilInstruction(CilOpCodes.Xor));
    }
}
