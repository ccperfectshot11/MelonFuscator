using MelonFuscator.Engine;

var log = new Logger();
PrintBanner();

if (args.Length == 0 || args[0] is "-h" or "--help" or "/?")
{
    PrintHelp();
    return 0;
}

// First positional argument is the input path.
var options = ObfuscationOptions.FromPreset(ObfuscationPreset.Melon);
options.InputPath = args[0];

for (int i = 1; i < args.Length; i++)
{
    var a = args[i];
    switch (a)
    {
        case "-o":
        case "--output":
            options.OutputPath = RequireValue(args, ref i, a);
            break;
        case "--preset":
            var p = RequireValue(args, ref i, a).ToLowerInvariant();
            var preset = p switch
            {
                "light" => ObfuscationPreset.Light,
                "melon" => ObfuscationPreset.Melon,
                "max" => ObfuscationPreset.Max,
                _ => throw new ArgumentException($"Unknown preset: {p}")
            };
            var keptIn = options.InputPath;
            var keptOut = options.OutputPath;
            options = ObfuscationOptions.FromPreset(preset);
            options.InputPath = keptIn;
            options.OutputPath = keptOut;
            break;
        case "--seed":
            options.Seed = int.Parse(RequireValue(args, ref i, a));
            break;
        case "--alphabet":
            options.RenameAlphabetSize = int.Parse(RequireValue(args, ref i, a));
            break;
        case "--verbose":
            log.Verbose = true;
            break;
        case "--no-verify":
            options.SelfVerify = false;
            break;
        case "--no-melon":
            options.MelonLoaderFriendly = false;
            break;
        // Per-protection toggles.
        case "--no-rename": options.Rename = false; break;
        case "--no-strings": options.EncryptStrings = false; break;
        case "--no-proxy": options.ProxyCalls = false; break;
        case "--no-flow": options.ControlFlow = false; break;
        case "--flatten": options.Flatten = true; break;
        case "--no-flatten": options.Flatten = false; break;
        case "--unicode": options.UnicodeNames = true; break;
        case "--no-antidebug": options.AntiDebug = false; break;
        case "--no-antitamper": options.AntiTamper = false; break;
        case "--no-anti": options.AntiDecompiler = false; break;
        default:
            log.Warn($"Ignoring unknown argument: {a}");
            break;
    }
}

var engine = new ObfuscationEngine(log);
var ok = engine.Run(options);
return ok ? 0 : 1;

static string RequireValue(string[] args, ref int i, string flag)
{
    if (i + 1 >= args.Length)
        throw new ArgumentException($"Missing value for {flag}");
    return args[++i];
}

static void PrintBanner()
{
    var old = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Magenta;
    Console.WriteLine();
    Console.WriteLine($"  {MelonFuscatorInfo.Name} v{MelonFuscatorInfo.Version}");
    Console.WriteLine("  aggressive, MelonLoader-friendly .NET obfuscator");
    Console.ForegroundColor = old;
    Console.WriteLine();
}

static void PrintHelp()
{
    Console.WriteLine("Usage:");
    Console.WriteLine("  MelonFuscator <input.dll> [options]");
    Console.WriteLine();
    Console.WriteLine("Options:");
    Console.WriteLine("  -o, --output <path>    Output file (default: <input>.obf.dll)");
    Console.WriteLine("  --preset <name>        light | melon | max        (default: melon)");
    Console.WriteLine("  --seed <int>           Deterministic RNG seed");
    Console.WriteLine("  --alphabet <int>       Rename alphabet size 16-45 (default: 32; entropy ~log2)");
    Console.WriteLine("  --verbose              Verbose logging");
    Console.WriteLine("  --no-verify            Skip the MelonLoader self-check");
    Console.WriteLine("  --no-melon             Do not treat input as a MelonLoader mod");
    Console.WriteLine();
    Console.WriteLine("  --flatten / --no-flatten   Control-flow flattening (on at 'max')");
    Console.WriteLine("  --unicode                  Unicode rename alphabet (experimental)");
    Console.WriteLine();
    Console.WriteLine("  Disable individual protections:");
    Console.WriteLine("  --no-rename  --no-strings  --no-proxy  --no-flow");
    Console.WriteLine("  --no-antidebug  --no-antitamper  --no-anti");
    Console.WriteLine();
    Console.WriteLine("Examples:");
    Console.WriteLine("  MelonFuscator MyMod.dll --preset max");
    Console.WriteLine("  MelonFuscator MyMod.dll -o out/MyMod.dll --seed 1337 --no-antidebug");
}
