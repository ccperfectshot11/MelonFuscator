using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace MelonFuscator.Engine.Protections;

/// <summary>
/// Control-flow flattening. Eligible code is split into basic blocks driven by a switch-
/// dispatcher on a state variable in randomized order, destroying the structured flow so
/// decompilers emit goto-soup or fail, while the CLR JIT runs it perfectly.
///
/// Coverage:
///   - Non-exception methods are flattened whole.
///   - For methods WITH exception handlers, each self-contained 'try' body (one that does not
///     itself contain another handler) is flattened as an independent region: a dispatcher
///     local to the try, entered by fall-through, with 'leave'/'throw' kept in place as region
///     terminals. This preserves handler semantics exactly (no branch is created into or out of
///     a protected region) while still scattering the try's interior.
///   - Blocks whose entry leaves values on the stack (ternary, short-circuit) use STACK-SPILLING.
///   - 'switch' opcodes are supported. Stack depth/types come from <see cref="StackTyper"/>.
///
/// Anything not provably safe is left untouched, so enabling this can never corrupt a method.
/// </summary>
public sealed class FlattenProtection : IProtection
{
    public string Name => "Control-Flow Flattening";
    public bool IsEnabled(ObfuscationOptions o) => o.Flatten;

    public void Execute(ObfuscationContext ctx)
    {
        var holder = CilHelpers.CreateStaticHolder(ctx.Module, ctx.Names.Next());
        var opaque = new FieldDefinition(ctx.Names.Next(),
            FieldAttributes.Public | FieldAttributes.Static, ctx.Module.CorLibTypeFactory.Int32);
        holder.Fields.Add(opaque);
        SeedZeroField(ctx.Module, holder, opaque);   // opaque == 0 at runtime, but unprovable

        int flattenedMethods = 0, flattenedRegions = 0, ehRegions = 0, skipped = 0;
        var reasons = new Dictionary<string, int>();
        void Skip(string why) { reasons.TryGetValue(why, out int c); reasons[why] = c + 1; }

        foreach (var type in ctx.Module.GetAllTypes())
        {
            foreach (var method in type.Methods)
            {
                var body = method.CilMethodBody;
                if (body == null) continue;

                int before = flattenedRegions;
                if (body.ExceptionHandlers.Count == 0)
                {
                    if (FlattenWholeMethod(ctx, method, opaque, Skip)) flattenedRegions++;
                }
                else
                {
                    int r = FlattenTryBodies(ctx, method, opaque, Skip);
                    flattenedRegions += r;
                    ehRegions += r;
                }
                if (flattenedRegions > before) flattenedMethods++; else skipped++;
            }
        }
        ctx.Log.Step($"flattened {flattenedMethods} method(s) / {flattenedRegions} region(s) ({ehRegions} inside try bodies), left {skipped} untouched");
        if (ctx.Log.Verbose)
            foreach (var kv in reasons.OrderByDescending(k => k.Value))
                ctx.Log.Debug($"skip[{kv.Key}] = {kv.Value}");
    }

    // ---- Whole-method flattening (no exception handlers). --------------------------------------
    private static bool FlattenWholeMethod(ObfuscationContext ctx, MethodDefinition method, FieldDefinition opaque, Action<string> onSkip)
    {
        var body = method.CilMethodBody!;
        var instrs = body.Instructions;
        instrs.CalculateOffsets();
        var types = StackTyper.Compute(method, out var bail);
        if (types == null) { onSkip("stacktyper:" + bail); return false; }
        var offsetToIndex = BuildOffsetMap(instrs);

        var flat = FlattenRange(ctx, method, instrs, types, offsetToIndex, 0, instrs.Count, opaque, onSkip);
        if (flat == null) return false;

        instrs.Clear();
        foreach (var ins in flat) instrs.Add(ins);
        instrs.CalculateOffsets();
        return true;
    }

    // ---- Flatten each self-contained try body of an exception method. -------------------------
    private static int FlattenTryBodies(ObfuscationContext ctx, MethodDefinition method, FieldDefinition opaque, Action<string> onSkip)
    {
        var body = method.CilMethodBody!;
        var instrs = body.Instructions;
        instrs.CalculateOffsets();
        var types = StackTyper.Compute(method, out var bail);
        if (types == null) { onSkip("stacktyper:" + bail); return 0; }
        var offsetToIndex = BuildOffsetMap(instrs);

        // Every EH boundary instruction index (used to detect nesting).
        var boundaries = new SortedSet<int>();
        void AddB(ICilLabel? l) { int i = Resolve(offsetToIndex, l); if (i >= 0) boundaries.Add(i); }
        foreach (var eh in body.ExceptionHandlers)
        {
            AddB(eh.TryStart); AddB(eh.TryEnd);
            AddB(eh.HandlerStart); AddB(eh.HandlerEnd);
            AddB(eh.FilterStart);
        }

        // Collect candidate leaf regions: try bodies, finally/fault handler bodies, and catch
        // handler bodies (minus their exception-consuming prologue). "leaf" = no EH boundary
        // strictly inside, so we never reorder blocks across a nested handler.
        bool IsLeaf(int lo, int hi) => !boundaries.Any(b => b > lo && b < hi);
        var ranges = new SortedSet<(int lo, int hi)>();

        foreach (var eh in body.ExceptionHandlers)
        {
            int tlo = Resolve(offsetToIndex, eh.TryStart), thi = Resolve(offsetToIndex, eh.TryEnd);
            if (tlo >= 0 && thi > tlo && IsLeaf(tlo, thi) && types[tlo]?.Count == 0)
                ranges.Add((tlo, thi));

            int hlo = Resolve(offsetToIndex, eh.HandlerStart), hhi = Resolve(offsetToIndex, eh.HandlerEnd);
            if (hlo < 0 || hhi <= hlo || !IsLeaf(hlo, hhi)) continue;

            if (eh.HandlerType is CilExceptionHandlerType.Finally or CilExceptionHandlerType.Fault)
            {
                if (types[hlo]?.Count == 0) ranges.Add((hlo, hhi));
            }
            else if (eh.HandlerType == CilExceptionHandlerType.Exception)
            {
                // The exception object is on the stack at entry; flatten from the first point
                // where the stack is empty again (after it is stored/popped). The prologue stays
                // in place and falls through into the flattened region.
                int split = -1;
                for (int j = hlo; j < hhi; j++)
                    if (types[j]?.Count == 0) { split = j; break; }
                if (split > hlo && hhi - split >= 6) ranges.Add((split, hhi));
            }
            // Filter handlers are left untouched.
        }

        var plan = new List<(int lo, int hi, List<CilInstruction> flat)>();
        foreach (var (lo, hi) in ranges)
        {
            var flat = FlattenRange(ctx, method, instrs, types, offsetToIndex, lo, hi, opaque, onSkip);
            if (flat == null) continue;
            plan.Add((lo, hi, flat));
        }
        if (plan.Count == 0) return 0;

        plan.Sort((a, b) => a.lo.CompareTo(b.lo));

        // Rebuild the body: copy originals by reference, substituting each flattened range.
        // Track the first emitted instruction of each flattened range to fix TryStart labels.
        var firstOfRange = new Dictionary<int, CilInstruction>();
        var rebuilt = new List<CilInstruction>();
        int idx = 0, p = 0;
        int n = instrs.Count;
        while (idx < n)
        {
            if (p < plan.Count && idx == plan[p].lo)
            {
                firstOfRange[plan[p].lo] = plan[p].flat[0];
                rebuilt.AddRange(plan[p].flat);
                idx = plan[p].hi;
                p++;
            }
            else
            {
                rebuilt.Add(instrs[idx]);
                idx++;
            }
        }

        // Remap EVERY EH boundary label whose target instruction became the start of a flattened
        // region. This must cover the exclusive ends too: e.g. an outer try/finally's TryEnd
        // equals the finally's start, so flattening the finally moves that boundary as well.
        ICilLabel? Remap(ICilLabel? label)
        {
            int i = Resolve(offsetToIndex, label);
            return i >= 0 && firstOfRange.TryGetValue(i, out var first) ? new CilInstructionLabel(first) : label;
        }
        foreach (var eh in body.ExceptionHandlers)
        {
            eh.TryStart = Remap(eh.TryStart);
            eh.TryEnd = Remap(eh.TryEnd);
            eh.HandlerStart = Remap(eh.HandlerStart);
            eh.HandlerEnd = Remap(eh.HandlerEnd);
            if (eh.FilterStart != null) eh.FilterStart = Remap(eh.FilterStart);
        }

        instrs.Clear();
        foreach (var ins in rebuilt) instrs.Add(ins);
        instrs.CalculateOffsets();
        return plan.Count;
    }

    // ---- Core: flatten instructions [lo, hi) into a fresh instruction list, or null to bail. ---
    private static List<CilInstruction>? FlattenRange(ObfuscationContext ctx, MethodDefinition method,
        CilInstructionCollection instrs, IReadOnlyList<TypeSignature?>?[] types, Dictionary<int, int> offsetToIndex,
        int lo, int hi, FieldDefinition opaque, Action<string> onSkip)
    {
        var body = method.CilMethodBody!;
        if (hi - lo < 6) { onSkip("tiny"); return null; }

        // Reject unsupported terminators up front.
        for (int i = lo; i < hi; i++)
            if (instrs[i].OpCode.Code == CilCode.Jmp) { onSkip("jmp"); return null; }

        // ---- Leaders.
        var leaders = new SortedSet<int> { lo };
        for (int i = lo; i < hi; i++)
        {
            var last = instrs[i];
            var code = last.OpCode.Code;
            if (code == CilCode.Switch)
            {
                if (last.Operand is not IEnumerable<ICilLabel> labels) { onSkip("cfg"); return null; }
                foreach (var l in labels)
                {
                    int t = Resolve(offsetToIndex, l);
                    if (t < lo || t >= hi) { onSkip("escapes-range"); return null; }
                    leaders.Add(t);
                }
                if (i + 1 < hi) leaders.Add(i + 1);
            }
            else if (IsTerminal(code))
            {
                if (i + 1 < hi) leaders.Add(i + 1);
            }
            else
            {
                var fc = last.OpCode.FlowControl;
                if (fc is CilFlowControl.Branch or CilFlowControl.ConditionalBranch)
                {
                    if (last.Operand is not ICilLabel lbl) { onSkip("cfg"); return null; }
                    int t = Resolve(offsetToIndex, lbl);
                    if (t < lo || t >= hi) { onSkip("escapes-range"); return null; }
                    leaders.Add(t);
                    if (i + 1 < hi) leaders.Add(i + 1);
                }
            }
        }

        var blockStart = leaders.ToList();
        int k = blockStart.Count;
        if (k < 3) { onSkip("few-blocks"); return null; }

        var leaderToBlock = new Dictionary<int, int>(k);
        for (int b = 0; b < k; b++) leaderToBlock[blockStart[b]] = b;

        // ---- Entry depth/types + spill locals.
        var entryDepth = new int[k];
        var spillLocals = new CilLocalVariable[k][];
        for (int b = 0; b < k; b++)
        {
            var st = types[blockStart[b]];
            if (st == null) { onSkip("unreachable-leader"); return null; }
            entryDepth[b] = st.Count;
            if (b == 0 && st.Count != 0) { onSkip("entry-nonempty"); return null; }
            if (st.Count == 0) { spillLocals[b] = null; continue; }

            var locals = new CilLocalVariable[st.Count];
            for (int q = 0; q < st.Count; q++)
            {
                var sig = StackTyper.SpillType(ctx.Module, st[q]);
                if (sig == null) { onSkip("nonspillable-stack"); return null; }
                locals[q] = new CilLocalVariable(sig);
                body.LocalVariables.Add(locals[q]);
            }
            spillLocals[b] = locals;
        }

        // ---- Validate terminators / depth consistency before committing.
        for (int b = 0; b < k; b++)
        {
            int end = (b + 1 < k) ? blockStart[b + 1] : hi;
            var last = instrs[end - 1];
            var code = last.OpCode.Code;
            var fc = last.OpCode.FlowControl;

            if (code == CilCode.Switch)
            {
                if (b + 1 >= k) { onSkip("no-fallthrough"); return null; }
                int sDepth = types[end]!.Count;
                foreach (var l in (IEnumerable<ICilLabel>)last.Operand!)
                {
                    if (!leaderToBlock.TryGetValue(Resolve(offsetToIndex, l), out int tb)) { onSkip("bad-target"); return null; }
                    if (entryDepth[tb] != sDepth) { onSkip("depth-mismatch"); return null; }
                }
                if (entryDepth[b + 1] != sDepth) { onSkip("depth-mismatch"); return null; }
            }
            else if (IsTerminal(code))
            {
                // leave / throw / rethrow / ret / endfinally / endfilter: nothing to validate.
            }
            else if (fc is CilFlowControl.Branch)
            {
                if (!leaderToBlock.TryGetValue(Resolve(offsetToIndex, (ICilLabel)last.Operand!), out int tb)) { onSkip("bad-target"); return null; }
                if (entryDepth[tb] != types[end - 1]!.Count) { onSkip("depth-mismatch"); return null; }
            }
            else if (fc is CilFlowControl.ConditionalBranch)
            {
                if (!leaderToBlock.TryGetValue(Resolve(offsetToIndex, (ICilLabel)last.Operand!), out int tb)) { onSkip("bad-target"); return null; }
                if (b + 1 >= k) { onSkip("no-fallthrough"); return null; }
                int fallDepth = types[end]!.Count;
                if (entryDepth[tb] != fallDepth || entryDepth[b + 1] != fallDepth) { onSkip("depth-mismatch"); return null; }
            }
            else
            {
                if (b + 1 >= k) { onSkip("no-fallthrough"); return null; }
                if (entryDepth[b + 1] != types[end]!.Count) { onSkip("depth-mismatch"); return null; }
            }
        }

        // ---- Randomized state ids.
        var stateForBlock = Enumerable.Range(0, k).ToList();
        for (int i = k - 1; i > 0; i--)
        {
            int j = ctx.Rng.Next(i + 1);
            (stateForBlock[i], stateForBlock[j]) = (stateForBlock[j], stateForBlock[i]);
        }

        var stateLocal = new CilLocalVariable(ctx.Module.CorLibTypeFactory.Int32);
        body.LocalVariables.Add(stateLocal);

        var dispatchLoad = new CilInstruction(CilOpCodes.Ldloc, stateLocal);
        var switchInstr = new CilInstruction(CilOpCodes.Switch);
        var dispatchLabel = new CilInstructionLabel(dispatchLoad);
        var blockStartLabels = new CilInstructionLabel[k];
        var output = new List<CilInstruction>();

        CilInstruction TransferTo(int targetBlock)
        {
            int outStart = output.Count;
            var spill = spillLocals[targetBlock];
            if (spill != null)
                for (int q = spill.Length - 1; q >= 0; q--)
                    output.Add(new CilInstruction(CilOpCodes.Stloc, spill[q]));
            EmitSetState(output, stateLocal, stateForBlock[targetBlock], opaque);
            output.Add(new CilInstruction(CilOpCodes.Br, dispatchLabel));
            return output[outStart];
        }

        EmitSetState(output, stateLocal, stateForBlock[0], opaque);
        output.Add(new CilInstruction(CilOpCodes.Br, dispatchLabel));
        output.Add(dispatchLoad);
        output.Add(switchInstr);
        output.Add(new CilInstruction(CilOpCodes.Br, dispatchLabel));   // default -> re-dispatch

        for (int b = 0; b < k; b++)
        {
            int start = blockStart[b];
            int end = (b + 1 < k) ? blockStart[b + 1] : hi;
            var last = instrs[end - 1];
            var code = last.OpCode.Code;
            var fc = last.OpCode.FlowControl;

            int outStart = output.Count;
            var reload = spillLocals[b];
            if (reload != null)
                for (int q = 0; q < reload.Length; q++)
                    output.Add(new CilInstruction(CilOpCodes.Ldloc, reload[q]));

            if (code == CilCode.Switch)
            {
                for (int i = start; i < end; i++) output.Add(instrs[i]);
                TransferTo(b + 1);
                var newLabels = new List<ICilLabel>();
                foreach (var l in (IEnumerable<ICilLabel>)last.Operand!)
                    newLabels.Add(new CilInstructionLabel(TransferTo(leaderToBlock[Resolve(offsetToIndex, l)])));
                last.Operand = newLabels;
            }
            else if (IsTerminal(code))
            {
                for (int i = start; i < end; i++) output.Add(instrs[i]);   // keep leave/throw/ret/... as-is
            }
            else if (fc is CilFlowControl.Branch)
            {
                for (int i = start; i < end - 1; i++) output.Add(instrs[i]);   // drop the br
                TransferTo(leaderToBlock[Resolve(offsetToIndex, (ICilLabel)last.Operand!)]);
            }
            else if (fc is CilFlowControl.ConditionalBranch)
            {
                for (int i = start; i < end; i++) output.Add(instrs[i]);
                TransferTo(b + 1);
                var takenFirst = TransferTo(leaderToBlock[Resolve(offsetToIndex, (ICilLabel)last.Operand!)]);
                last.Operand = new CilInstructionLabel(takenFirst);
            }
            else
            {
                for (int i = start; i < end; i++) output.Add(instrs[i]);
                TransferTo(b + 1);
            }

            blockStartLabels[b] = new CilInstructionLabel(output[outStart]);
        }

        var switchLabels = new ICilLabel[k];
        for (int b = 0; b < k; b++) switchLabels[stateForBlock[b]] = blockStartLabels[b];
        switchInstr.Operand = switchLabels.ToList();
        return output;
    }

    private static bool IsTerminal(CilCode code) => code is
        CilCode.Ret or CilCode.Throw or CilCode.Rethrow
        or CilCode.Leave or CilCode.Leave_S
        or CilCode.Endfinally or CilCode.Endfilter;

    private static CilInstruction EmitSetState(List<CilInstruction> output, CilLocalVariable state, int value, FieldDefinition opaque)
    {
        var first = new CilInstruction(CilOpCodes.Ldc_I4, value);
        output.Add(first);
        output.Add(new CilInstruction(CilOpCodes.Ldsfld, opaque));
        output.Add(new CilInstruction(CilOpCodes.Xor));
        output.Add(new CilInstruction(CilOpCodes.Stloc, state));
        return first;
    }

    // opaque = (t*(t+1)) & 1 with t = Environment.TickCount: 0 at runtime, but unprovable.
    private static void SeedZeroField(ModuleDefinition module, TypeDefinition holder, FieldDefinition field)
    {
        var tickCount = CilHelpers.ImportStatic(module, "System", "Environment", "get_TickCount",
            module.CorLibTypeFactory.Int32);

        var cctor = new MethodDefinition(".cctor",
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig
            | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName,
            MethodSignature.CreateStatic(module.CorLibTypeFactory.Void));
        holder.Methods.Add(cctor);

        var b = new CilMethodBody();
        cctor.CilMethodBody = b;
        var t = new CilLocalVariable(module.CorLibTypeFactory.Int32);
        b.LocalVariables.Add(t);
        var n = b.Instructions;
        n.Add(new CilInstruction(CilOpCodes.Call, tickCount));
        n.Add(new CilInstruction(CilOpCodes.Stloc, t));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, t));
        n.Add(new CilInstruction(CilOpCodes.Ldloc, t));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
        n.Add(new CilInstruction(CilOpCodes.Add));
        n.Add(new CilInstruction(CilOpCodes.Mul));
        n.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
        n.Add(new CilInstruction(CilOpCodes.And));
        n.Add(new CilInstruction(CilOpCodes.Stsfld, field));
        n.Add(new CilInstruction(CilOpCodes.Ret));
        n.CalculateOffsets();
    }

    private static Dictionary<int, int> BuildOffsetMap(CilInstructionCollection instrs)
    {
        var map = new Dictionary<int, int>(instrs.Count);
        for (int i = 0; i < instrs.Count; i++) map[instrs[i].Offset] = i;
        return map;
    }

    private static int Resolve(Dictionary<int, int> offsetToIndex, ICilLabel? label)
        => label != null && offsetToIndex.TryGetValue(label.Offset, out int idx) ? idx : -1;
}
