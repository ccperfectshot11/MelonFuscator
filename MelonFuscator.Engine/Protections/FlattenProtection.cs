using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Control-flow flattening. Each eligible method is split into basic blocks that are then
/// driven by a switch-dispatcher on a state variable, in randomized order. This destroys the
/// original structured control flow, so structuring decompilers (ICSharpCode / dnSpy / ILSpy)
/// either emit unreadable goto-soup or throw during decompilation - while the CLR JIT runs it
/// perfectly, so MelonLoader is unaffected.
///
/// For safety we only flatten methods that:
///   - have no exception handlers,
///   - contain no 'switch' opcode,
///   - have all basic-block boundaries at eval-stack depth 0.
/// Anything else is left untouched (the opaque-predicate pass still applies).
/// </summary>
public sealed class FlattenProtection : IProtection
{
    public string Name => "Control-Flow Flattening";
    public bool IsEnabled(ObfuscationOptions o) => o.Flatten;

    public void Execute(ObfuscationContext ctx)
    {
        int flattened = 0, skipped = 0;
        foreach (var type in ctx.Module.GetAllTypes())
        {
            foreach (var method in type.Methods)
            {
                var body = method.CilMethodBody;
                if (body == null) continue;
                if (TryFlatten(ctx, body)) flattened++;
                else skipped++;
            }
        }
        ctx.Log.Step($"flattened {flattened} method(s), left {skipped} untouched (EH/switch/stack)");
    }

    private static bool TryFlatten(ObfuscationContext ctx, CilMethodBody body)
    {
        if (body.ExceptionHandlers.Count != 0) return false;

        var instrs = body.Instructions;
        int n = instrs.Count;
        if (n < 6) return false;

        instrs.CalculateOffsets();

        // No switch opcode (multi-target handling is out of scope).
        foreach (var ins in instrs)
            if (ins.OpCode.Code == CilCode.Switch)
                return false;

        // Linear eval-stack depth before each instruction; reset to 0 after unconditional exits.
        var depth = new int[n];
        for (int i = 0; i < n; i++)
        {
            int after;
            try { after = depth[i] - instrs[i].GetStackPopCount(body) + instrs[i].GetStackPushCount(); }
            catch { return false; }
            if (i + 1 < n)
            {
                var fc = instrs[i].OpCode.FlowControl;
                depth[i + 1] = (fc == CilFlowControl.Branch || fc == CilFlowControl.Return || fc == CilFlowControl.Throw)
                    ? 0 : after;
            }
        }

        // Leaders: index 0, every branch target, and the instruction after any branch/exit.
        var indexOf = new Dictionary<CilInstruction, int>(n);
        for (int i = 0; i < n; i++) indexOf[instrs[i]] = i;

        var leaders = new SortedSet<int> { 0 };
        for (int i = 0; i < n; i++)
        {
            var fc = instrs[i].OpCode.FlowControl;
            if (fc == CilFlowControl.Branch || fc == CilFlowControl.ConditionalBranch)
            {
                if (instrs[i].Operand is not ICilLabel lbl || lbl.Offset < 0) return false;
                var target = FindByOffset(instrs, lbl.Offset);
                if (target < 0) return false;
                leaders.Add(target);
                if (i + 1 < n) leaders.Add(i + 1);
            }
            else if (fc == CilFlowControl.Return || fc == CilFlowControl.Throw)
            {
                if (i + 1 < n) leaders.Add(i + 1);
            }
        }

        // All leaders must sit at stack depth 0.
        foreach (var L in leaders)
            if (depth[L] != 0) return false;

        var leaderList = leaders.ToList();
        int k = leaderList.Count;
        if (k < 3) return false;

        // Build blocks and a leader-index -> block-number map.
        var blockStart = leaderList;                       // block b starts at leaderList[b]
        var leaderToBlock = new Dictionary<int, int>();
        for (int b = 0; b < k; b++) leaderToBlock[blockStart[b]] = b;

        // Randomized state id per block.
        var stateForBlock = Enumerable.Range(0, k).ToList();
        for (int i = k - 1; i > 0; i--)
        {
            int j = ctx.Rng.Next(i + 1);
            (stateForBlock[i], stateForBlock[j]) = (stateForBlock[j], stateForBlock[i]);
        }

        // Validate EVERY block before mutating anything (so we never leave a half-rewritten body).
        for (int b = 0; b < k; b++)
        {
            int end = (b + 1 < k) ? blockStart[b + 1] : n;
            var last = instrs[end - 1];
            var fc = last.OpCode.FlowControl;

            if (fc == CilFlowControl.Branch || fc == CilFlowControl.ConditionalBranch)
            {
                int t = FindByOffset(instrs, ((ICilLabel)last.Operand!).Offset);
                if (t < 0 || !leaderToBlock.ContainsKey(t)) return false;
            }
            bool needsFallThrough = fc != CilFlowControl.Branch
                && fc != CilFlowControl.Return && fc != CilFlowControl.Throw;
            if (needsFallThrough && b + 1 >= k) return false;   // would fall off the method
        }

        var stateLocal = new CilLocalVariable(ctx.Module.CorLibTypeFactory.Int32);
        body.LocalVariables.Add(stateLocal);

        // Dispatcher skeleton.
        var dispatchLoad = new CilInstruction(CilOpCodes.Ldloc, stateLocal);
        var switchInstr = new CilInstruction(CilOpCodes.Switch);
        var blockStartLabels = new CilInstructionLabel[k];  // filled as blocks are emitted

        var output = new List<CilInstruction>();
        // prologue: state = stateForBlock[0]; goto dispatch;
        output.Add(new CilInstruction(CilOpCodes.Ldc_I4, stateForBlock[0]));
        output.Add(new CilInstruction(CilOpCodes.Stloc, stateLocal));
        output.Add(new CilInstruction(CilOpCodes.Br, new CilInstructionLabel(dispatchLoad)));
        // dispatcher
        output.Add(dispatchLoad);
        output.Add(switchInstr);
        output.Add(new CilInstruction(CilOpCodes.Br, new CilInstructionLabel(dispatchLoad))); // default -> re-dispatch

        var dispatchLabel = new CilInstructionLabel(dispatchLoad);

        // Emit blocks (in original order; dispatch controls execution).
        for (int b = 0; b < k; b++)
        {
            int start = blockStart[b];
            int end = (b + 1 < k) ? blockStart[b + 1] : n;   // exclusive
            var last = instrs[end - 1];
            var fc = last.OpCode.FlowControl;

            // The block label must point at the FIRST instruction we actually emit for it
            // (for a bare 'br' block the original br is dropped, so instrs[start] would be absent).
            int outStart = output.Count;

            if (fc == CilFlowControl.Return || fc == CilFlowControl.Throw)
            {
                for (int i = start; i < end; i++) output.Add(instrs[i]);
            }
            else if (fc == CilFlowControl.Branch)
            {
                for (int i = start; i < end - 1; i++) output.Add(instrs[i]);  // drop the br
                int tgt = leaderToBlock[FindByOffset(instrs, ((ICilLabel)last.Operand!).Offset)];
                EmitGoto(output, stateLocal, stateForBlock[tgt], dispatchLabel);
            }
            else if (fc == CilFlowControl.ConditionalBranch)
            {
                for (int i = start; i < end; i++) output.Add(instrs[i]);      // keep body + cond branch
                int tgtBlock = leaderToBlock[FindByOffset(instrs, ((ICilLabel)last.Operand!).Offset)];
                int fallBlock = leaderToBlock[end];                            // next leader
                // taken path stub
                var takenStub = new CilInstruction(CilOpCodes.Ldc_I4, stateForBlock[tgtBlock]);
                last.Operand = new CilInstructionLabel(takenStub);            // retarget cond branch
                // fall-through: state = fall; goto dispatch
                EmitGoto(output, stateLocal, stateForBlock[fallBlock], dispatchLabel);
                // taken: state = tgt; goto dispatch
                output.Add(takenStub);
                output.Add(new CilInstruction(CilOpCodes.Stloc, stateLocal));
                output.Add(new CilInstruction(CilOpCodes.Br, dispatchLabel));
            }
            else
            {
                // Falls through to the next block.
                if (b + 1 >= k) return false;
                for (int i = start; i < end; i++) output.Add(instrs[i]);
                EmitGoto(output, stateLocal, stateForBlock[b + 1], dispatchLabel);
            }

            blockStartLabels[b] = new CilInstructionLabel(output[outStart]);
        }

        // Wire the switch table: switchLabels[stateValue] -> block whose stateForBlock == stateValue.
        var switchLabels = new ICilLabel[k];
        for (int b = 0; b < k; b++) switchLabels[stateForBlock[b]] = blockStartLabels[b];
        switchInstr.Operand = switchLabels.ToList();

        // Replace the body.
        instrs.Clear();
        foreach (var ins in output) instrs.Add(ins);
        instrs.CalculateOffsets();
        return true;
    }

    private static void EmitGoto(List<CilInstruction> output, CilLocalVariable state, int value, ICilLabel dispatch)
    {
        output.Add(new CilInstruction(CilOpCodes.Ldc_I4, value));
        output.Add(new CilInstruction(CilOpCodes.Stloc, state));
        output.Add(new CilInstruction(CilOpCodes.Br, dispatch));
    }

    private static int FindByOffset(CilInstructionCollection instrs, int offset)
    {
        for (int i = 0; i < instrs.Count; i++)
            if (instrs[i].Offset == offset)
                return i;
        return -1;
    }
}
