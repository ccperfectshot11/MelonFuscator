namespace MelonFuscator.Engine.Protections;

/// <summary>A single obfuscation pass over the module.</summary>
public interface IProtection
{
    /// <summary>Human-readable name shown in the log.</summary>
    string Name { get; }

    /// <summary>Whether this protection is enabled by the current options.</summary>
    bool IsEnabled(ObfuscationOptions options);

    /// <summary>Runs the pass against the module in the context.</summary>
    void Execute(ObfuscationContext ctx);
}
