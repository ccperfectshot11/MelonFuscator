using AsmResolver.DotNet;
using MelonFuscator.Engine.Protections;

namespace MelonFuscator.Engine;

/// <summary>
/// Orchestrates the whole obfuscation pipeline: load -> analyze -> run protections
/// -> write -> self-verify against MelonLoader's rules.
/// </summary>
public sealed class ObfuscationEngine
{
    private readonly Logger _log;

    public ObfuscationEngine(Logger log) => _log = log;

    // The pipeline order. Renaming runs last so it also covers members injected by
    // earlier passes and gives us full control over the final entropy.
    private static IReadOnlyList<IProtection> BuildPipeline() => new IProtection[]
    {
        new StringEncryptionProtection(),
        new MutationProtection(),
        new DataEncryptionProtection(),
        new ConstantsProtection(),
        new ProxyCallProtection(),
        new FlattenProtection(),
        new ControlFlowProtection(),
        new AntiDebugProtection(),
        new AntiTamperProtection(),
        new AntiDecompilerProtection(),
        new DecompilerBombProtection(),
        new RenamerProtection(),
        new WatermarkProtection(),   // injected marker/watermark type names must survive renaming
        new IntegrityCheckProtection(),  // truly last: needs the final type count
    };

    public bool Run(ObfuscationOptions options)
    {
        if (!File.Exists(options.InputPath))
        {
            _log.Error($"Input file not found: {options.InputPath}");
            return false;
        }

        _log.Info($"Loading: {options.InputPath}");
        var module = ModuleDefinition.FromFile(options.InputPath);

        // Let the resolver find MelonLoader/UnityEngine assemblies next to the input,
        // so base-type walks (Resolve) succeed.
        var inputDir = Path.GetDirectoryName(Path.GetFullPath(options.InputPath))!;
        if (module.RuntimeContext.AssemblyResolver is AssemblyResolverBase arb)
            arb.SearchDirectories.Add(inputDir);

        // Optional runtime template module (reserved for future cloned helpers). All current
        // protections emit IL directly into the target, so this is not required.
        var runtimePath = Path.Combine(AppContext.BaseDirectory, "MelonFuscator.Runtime.dll");
        var runtimeModule = File.Exists(runtimePath) ? ModuleDefinition.FromFile(runtimePath) : null;

        var seed = options.Seed != 0 ? options.Seed : Environment.TickCount;
        var rng = new Random(seed);
        // Unicode letters are a disjoint character set added on top of retained ASCII names,
        // which raises the combined entropy. Use a smaller default alphabet so we stay under
        // MelonLoader's 5.5 ceiling (the self-check still guards the final value).
        if (options.UnicodeNames && options.RenameAlphabetSize == 32)
        {
            options.RenameAlphabetSize = 18;
            _log.Info("Unicode names: alphabet auto-set to 18 to keep entropy <= 5.5.");
        }

        var names = new NameGenerator(rng, options.RenameAlphabetSize, options.UnicodeNames);

        var ctx = new ObfuscationContext
        {
            Module = module,
            RuntimeModule = runtimeModule,
            Options = options,
            Log = _log,
            Rng = rng,
            Names = names,
            Cipher = new ByteCipher(rng),
        };

        _log.Info($"Seed: {seed}");

        // Collect every identifier referenced from a string literal BEFORE anything mutates
        // the module (string encryption would otherwise hide them). Members named like these
        // are treated as reflection targets and excluded from renaming.
        CollectReferencedNames(ctx);
        _log.Info($"Reflection-name guard: {ctx.Analysis.ReferencedNames.Count} names found in string literals.");

        // Analyze for MelonLoader specifics.
        if (options.MelonLoaderFriendly)
        {
            _log.Info("Analyzing MelonLoader metadata...");
            MelonLoaderAnalyzer.Analyze(ctx);
            if (ctx.Analysis.IsMelonAssembly)
                _log.Good($"MelonLoader mod detected ({ctx.Analysis.MelonTypes.Count} melon type(s)).");
            else
                _log.Warn("No MelonLoader attributes found - treating as a generic assembly.");
        }

        // Run the pipeline.
        foreach (var protection in BuildPipeline())
        {
            if (!protection.IsEnabled(options))
                continue;

            _log.Info($"Protection: {protection.Name}");
            try
            {
                protection.Execute(ctx);
            }
            catch (Exception ex)
            {
                _log.Error($"{protection.Name} failed: {ex.Message}");
                _log.Debug(ex.ToString());
                return false;
            }
        }

        // Fix up branch sizes: our insertions may have pushed short branches (br.s) out of
        // range. OptimizeMacros recomputes each branch to the smallest form that fits (long
        // where necessary), preventing "branch target too far" errors on write.
        FixBranchSizes(ctx);

        // Write output.
        var outPath = string.IsNullOrWhiteSpace(options.OutputPath)
            ? DefaultOutputPath(options.InputPath)
            : options.OutputPath;

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outPath))!);
        _log.Info($"Writing: {outPath}");
        module.Write(outPath);

        // Self-verify against MelonLoader's exact rules.
        if (options.SelfVerify)
        {
            _log.Info("Self-verifying (MelonLoader AssemblyVerifier rules)...");
            var result = MelonAssemblyVerifier.CheckFile(outPath);
            _log.Step($"types={result.TypeCount}, methods={result.MethodCount}, entropy={result.Entropy:F3}");
            if (result.Ok)
            {
                _log.Good($"MelonLoader-friendly: {result.Reason}");
            }
            else
            {
                _log.Error($"SELF-CHECK FAILED: {result.Reason}");
                _log.Error("The output would be REJECTED by MelonLoader. Adjust options and retry.");
                return false;
            }
        }

        _log.Good("Done.");
        return true;
    }

    // Collects all ldstr operands (and their dot/plus/backtick-separated segments) so the
    // renamer can avoid renaming members that are looked up by name at runtime.
    private static void CollectReferencedNames(ObfuscationContext ctx)
    {
        var set = ctx.Analysis.ReferencedNames;
        char[] seps = { '.', '+', ':', '`', '/', '\\', ' ', ',', '(', ')', '<', '>', '[', ']' };

        foreach (var type in ctx.Module.GetAllTypes())
        {
            foreach (var method in type.Methods)
            {
                var body = method.CilMethodBody;
                if (body == null) continue;
                foreach (var ins in body.Instructions)
                {
                    if (ins.OpCode.Code == AsmResolver.PE.DotNet.Cil.CilCode.Ldstr && ins.Operand is string s && s.Length > 0)
                    {
                        set.Add(s);
                        foreach (var part in s.Split(seps, StringSplitOptions.RemoveEmptyEntries))
                            if (part.Length > 1)
                                set.Add(part);
                    }
                }
            }
        }
    }

    private void FixBranchSizes(ObfuscationContext ctx)
    {
        int fixedCount = 0;
        foreach (var type in ctx.Module.GetAllTypes())
        {
            foreach (var method in type.Methods)
            {
                var body = method.CilMethodBody;
                if (body == null) continue;
                try
                {
                    body.Instructions.OptimizeMacros();
                    fixedCount++;
                }
                catch
                {
                    // Fallback: force every branch to its long form (never overflows).
                    try { body.Instructions.ExpandMacros(); } catch { }
                }
            }
        }
        ctx.Log.Step($"recomputed branch sizes for {fixedCount} method bodies");
    }

    private static string DefaultOutputPath(string input)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(input))!;
        var name = Path.GetFileNameWithoutExtension(input);
        var ext = Path.GetExtension(input);
        return Path.Combine(dir, $"{name}.obf{ext}");
    }
}
