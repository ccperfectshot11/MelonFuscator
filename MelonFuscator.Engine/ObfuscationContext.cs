using AsmResolver.DotNet;

namespace MelonFuscator.Engine;

/// <summary>Result of the MelonLoader analysis of the assembly.</summary>
public sealed class MelonAnalysis
{
    public bool IsMelonAssembly { get; set; }
    public List<TypeDefinition> MelonTypes { get; } = new();  // classes inheriting MelonMod/MelonPlugin
    public HashSet<TypeDefinition> ProtectedTypes { get; } = new();
    public HashSet<MethodDefinition> ProtectedMethods { get; } = new();
    public HashSet<FieldDefinition> ProtectedFields { get; } = new();

    /// <summary>
    /// Every identifier that appears inside a string literal (ldstr) anywhere in the module.
    /// Members with a name in this set are likely looked up by reflection (AccessTools.Method,
    /// Type.GetType, GetMethod, manual Harmony patching, ...) and must NOT be renamed.
    /// Collected before string encryption.
    /// </summary>
    public HashSet<string> ReferencedNames { get; } = new(StringComparer.Ordinal);
}

/// <summary>
/// The context passed between all protections. Holds the module being obfuscated,
/// the runtime module (clone template), the options, the name generator and the analysis.
/// </summary>
public sealed class ObfuscationContext
{
    public required ModuleDefinition Module { get; init; }
    public required ModuleDefinition RuntimeModule { get; init; }
    public required ObfuscationOptions Options { get; init; }
    public required Logger Log { get; init; }
    public required Random Rng { get; init; }
    public required NameGenerator Names { get; init; }
    public required ByteCipher Cipher { get; init; }
    public MelonAnalysis Analysis { get; set; } = new();
}
