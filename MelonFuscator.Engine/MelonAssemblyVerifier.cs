using System.Globalization;
using AsmResolver.DotNet;

namespace MelonFuscator.Engine;

/// <summary>
/// A 1:1 reimplementation of the rules in MelonLoader\Utils\AssemblyVerifier.cs.
/// We use it as a SELF-CHECK after obfuscation: if the output passes here it will
/// also pass MelonLoader's real verifier (IL2CPP / NET6+ games).
/// </summary>
public static class MelonAssemblyVerifier
{
    // Exactly the allowed symbol set from MelonLoader.
    private static readonly HashSet<char> AllowedSymbols = new()
    {
        '_','<','>','`','.','=','-','|',',','[',']','$',':','@','(',')','?','{','}','!'
    };

    public sealed class Result
    {
        public bool Ok { get; set; }
        public string? Reason { get; set; }
        public double Entropy { get; set; }
        public int TypeCount { get; set; }
        public int MethodCount { get; set; }
    }

    // Identical to MelonLoader's IsNameValid.
    private static bool IsNameValid(string? name)
    {
        if (name is null)
            return false;

        foreach (char c in name)
        {
            var cat = CharUnicodeInfo.GetUnicodeCategory(c);
            if (cat is UnicodeCategory.UppercaseLetter
                or UnicodeCategory.LowercaseLetter
                or UnicodeCategory.TitlecaseLetter
                or UnicodeCategory.ModifierLetter
                or UnicodeCategory.OtherLetter
                or UnicodeCategory.LetterNumber
                or UnicodeCategory.DecimalDigitNumber
                or UnicodeCategory.ConnectorPunctuation
                or UnicodeCategory.NonSpacingMark
                or UnicodeCategory.SpacingCombiningMark
                or UnicodeCategory.Format)
                continue;

            if (AllowedSymbols.Contains(c))
                continue;

            return false;
        }
        return true;
    }

    private static void CountChars(string str, Dictionary<char, int> map)
    {
        foreach (char c in str)
        {
            if (map.TryGetValue(c, out var n))
                map[c] = n + 1;
            else
                map[c] = 1;
        }
    }

    /// <summary>Verifies an AsmResolver module against exactly MelonLoader's rules.</summary>
    public static Result Check(ModuleDefinition module)
    {
        var result = new Result();

        // Rule 1: exactly one module in the assembly.
        if (module.Assembly is null || module.Assembly.Modules.Count != 1)
        {
            result.Ok = false;
            result.Reason = "Invalid module count (must be exactly 1).";
            return result;
        }

        var allTypes = module.GetAllTypes().ToList();
        var symbolCounts = new Dictionary<char, int>();
        int methodCount = 0;

        foreach (var type in allTypes)
        {
            var ns = type.Namespace?.Value;
            var typeName = type.Name?.Value ?? "";

            // Rule 2: a delegate (: System.MulticastDelegate) may not have fields.
            var bt = type.BaseType;
            if (bt != null && bt.Name?.Value == "MulticastDelegate" && bt.Namespace?.Value == "System")
            {
                if (type.Fields.Count != 0)
                {
                    result.Ok = false;
                    result.Reason = $"Delegate type '{type.FullName}' has fields (forbidden).";
                    return result;
                }
            }

            // Rule 3: valid namespace (if present).
            if (ns != null && !IsNameValid(ns))
            {
                result.Ok = false;
                result.Reason = $"Invalid namespace: \"{ns}\".";
                return result;
            }

            // Rule 4: valid type name.
            if (!IsNameValid(typeName))
            {
                result.Ok = false;
                result.Reason = $"Invalid type name: \"{typeName}\".";
                return result;
            }

            CountChars(typeName, symbolCounts);

            // Rule 5: valid method name + count for entropy.
            foreach (var method in type.Methods)
            {
                var mn = method.Name?.Value ?? "";
                if (!IsNameValid(mn))
                {
                    result.Ok = false;
                    result.Reason = $"Invalid method name: \"{mn}\" in {type.FullName}.";
                    return result;
                }
                CountChars(mn, symbolCounts);
                methodCount++;
            }
        }

        result.TypeCount = allTypes.Count;
        result.MethodCount = methodCount;

        // Below 25 entries MelonLoader skips the entropy check -> passes automatically.
        if (allTypes.Count + methodCount < 25)
        {
            result.Ok = true;
            result.Reason = "OK (too few symbols for the entropy check).";
            return result;
        }

        double totalChars = symbolCounts.Values.Sum();
        double totalEntropy = symbolCounts.Values.Sum(v => v * Math.Log2(v / totalChars));
        totalEntropy /= -totalChars;
        result.Entropy = totalEntropy;

        // Rule 6: entropy must be in [4.0, 5.5].
        if (totalEntropy is < 4 or > 5.5)
        {
            result.Ok = false;
            result.Reason = $"Invalid entropy: {totalEntropy:F3} (must be in [4.0, 5.5]).";
            return result;
        }

        result.Ok = true;
        result.Reason = $"OK (entropy {totalEntropy:F3}).";
        return result;
    }

    /// <summary>Verifies a file on disk directly, exactly like MelonLoader does.</summary>
    public static Result CheckFile(string path)
    {
        var module = ModuleDefinition.FromFile(path);
        return Check(module);
    }
}
