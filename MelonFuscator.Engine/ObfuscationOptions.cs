namespace MelonFuscator.Engine;

/// <summary>
/// Quick presets that enable a set of protections.
/// </summary>
public enum ObfuscationPreset
{
    /// <summary>Renaming + string encryption only. Safest.</summary>
    Light,
    /// <summary>Recommended balance for MelonLoader mods.</summary>
    Melon,
    /// <summary>Everything at maximum. As aggressive as possible while staying MelonLoader-friendly.</summary>
    Max
}

/// <summary>
/// All settings for the obfuscation process. Every protection has a flag.
/// </summary>
public sealed class ObfuscationOptions
{
    public string InputPath { get; set; } = "";
    public string OutputPath { get; set; } = "";

    /// <summary>Detect MelonLoader attributes and protect what must not break.</summary>
    public bool MelonLoaderFriendly { get; set; } = true;

    /// <summary>Run the self-check (MelonLoader's exact rules) at the end.</summary>
    public bool SelfVerify { get; set; } = true;

    // --- Individual protections ---
    public bool Rename { get; set; } = true;
    public bool EncryptStrings { get; set; } = true;
    public bool EncryptConstants { get; set; } = true;  // numeric ldc.i4 constants
    public bool ProxyCalls { get; set; } = true;
    public bool ControlFlow { get; set; } = true;   // opaque predicates
    public bool Flatten { get; set; } = true;        // switch-dispatcher control-flow flattening
    public bool AntiDebug { get; set; } = true;
    public bool AntiTamper { get; set; } = true;
    public bool AntiDecompiler { get; set; } = true; // anti-dnSpy / anti-ILSpy / anti-de4dot

    /// <summary>Use a Unicode alphabet for renaming (still IsNameValid + entropy safe).</summary>
    public bool UnicodeNames { get; set; } = false;

    /// <summary>Seed for the random generator (0 = seeded from time).</summary>
    public int Seed { get; set; } = 0;

    /// <summary>
    /// Number of distinct characters used for renaming. Controls entropy:
    /// entropy ~ log2(AlphabetSize). MelonLoader requires entropy in [4.0, 5.5],
    /// so ~24-40 is the safe zone. 32 => entropy ~5.0.
    /// </summary>
    public int RenameAlphabetSize { get; set; } = 32;

    public static ObfuscationOptions FromPreset(ObfuscationPreset preset)
    {
        var o = new ObfuscationOptions();
        switch (preset)
        {
            case ObfuscationPreset.Light:
                o.Rename = true;
                o.EncryptStrings = true;
                o.EncryptConstants = false;
                o.ProxyCalls = false;
                o.ControlFlow = false;
                o.Flatten = false;
                o.AntiDebug = false;
                o.AntiTamper = false;
                o.AntiDecompiler = true;
                break;
            case ObfuscationPreset.Melon:
                o.Rename = true;
                o.EncryptStrings = true;
                o.ProxyCalls = true;
                o.ControlFlow = true;
                o.Flatten = false;         // flattening is powerful but heavier; opt in via max/--flatten
                o.AntiDebug = true;
                o.AntiTamper = false;      // anti-tamper is risky with the verifier; off by default
                o.AntiDecompiler = true;
                break;
            case ObfuscationPreset.Max:
                o.Rename = true;
                o.EncryptStrings = true;
                o.ProxyCalls = true;
                o.ControlFlow = true;
                o.Flatten = true;
                o.AntiDebug = true;
                o.AntiTamper = true;
                o.AntiDecompiler = true;
                break;
        }
        return o;
    }
}
