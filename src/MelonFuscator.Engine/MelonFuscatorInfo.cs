namespace MelonFuscator.Engine;

/// <summary>Central product identity. Bump Version each release; it flows into the
/// banner, the watermark attribute and logs.</summary>
public static class MelonFuscatorInfo
{
    public const string Name = "MelonFuscator";
    public const string Version = "1.0.0";

    /// <summary>e.g. "MelonFuscator.v1.0.0" - used as the watermark value.</summary>
    public static string Watermark => $"{Name}.v{Version}";
}
