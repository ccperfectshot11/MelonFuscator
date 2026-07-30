using System.Text;

namespace MelonFuscator.Engine;

/// <summary>
/// Generates new names for renaming while respecting MelonLoader's constraints:
///   1) every character must be a valid identifier char (IsNameValid) -> we use ASCII letters only;
///   2) the Shannon entropy of the character distribution must be in [4.0, 5.5].
///
/// Key insight: with a uniform distribution over K distinct characters the entropy
/// tends to log2(K). So choosing K ~ 32 yields entropy ~5.0, exactly in MelonLoader's window.
/// </summary>
public sealed class NameGenerator
{
    // Full pool of available letters (all valid for IsNameValid).
    // Intentionally shuffled so generated names look chaotic.
    private const string MasterPool =
        "aQbWcErTdYfUgIhOjPkLlZmXnCvBpNqMsAwDeRtGyHuJiKoLpZxXcCvVbBnN";

    // Unicode pool: distinct Greek + Cyrillic lowercase letters. All are UnicodeCategory
    // LowercaseLetter, so MelonLoader's IsNameValid accepts them, yet they render as an
    // alien, near-Latin homoglyph soup. Distinct code points keep the entropy healthy.
    private const string UnicodePool =
        "αβγδεζηθικλμνξο" +
        "πρστυφχψω" +
        "абвгджзиклмнпрстфцчш";

    private readonly char[] _alphabet;
    private readonly Random _rng;
    private readonly HashSet<string> _used = new(StringComparer.Ordinal);

    public NameGenerator(Random rng, int alphabetSize, bool unicode = false)
    {
        _rng = rng;
        var pool = unicode ? UnicodePool : MasterPool;
        if (alphabetSize < 16) alphabetSize = 16;   // below 16 => entropy < 4 => rejected
        if (alphabetSize > 45) alphabetSize = 45;   // above ~45 => entropy > 5.5 => rejected

        // Build an alphabet of DISTINCT characters from the pool.
        var distinct = new List<char>();
        var seen = new HashSet<char>();
        foreach (var c in pool)
        {
            if (seen.Add(c))
                distinct.Add(c);
            if (distinct.Count >= alphabetSize)
                break;
        }
        _alphabet = distinct.ToArray();
    }

    /// <summary>Number of distinct characters actually used (for entropy estimation).</summary>
    public int AlphabetSize => _alphabet.Length;

    /// <summary>Theoretical (uniform) entropy of the generated names.</summary>
    public double TheoreticalEntropy => Math.Log2(_alphabet.Length);

    private char RandomChar() => _alphabet[_rng.Next(_alphabet.Length)];

    /// <summary>Generates a unique, random name with length between min and max.</summary>
    public string Next(int minLen = 8, int maxLen = 14)
    {
        for (int attempt = 0; attempt < 10000; attempt++)
        {
            int len = _rng.Next(minLen, maxLen + 1);
            var sb = new StringBuilder(len);
            for (int i = 0; i < len; i++)
                sb.Append(RandomChar());
            var name = sb.ToString();
            if (_used.Add(name))
                return name;
        }
        // Practically unreachable, but keep a fallback.
        var fallback = "z" + Guid.NewGuid().ToString("N");
        _used.Add(fallback);
        return fallback;
    }
}
