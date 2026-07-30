# MelonFuscator

An aggressive, **MelonLoader-friendly** .NET obfuscator, inspired by BitMono and ConfuserEx.

MelonFuscator protects [MelonLoader](https://github.com/LavaGang/MelonLoader) mods (Unity **Mono** and **IL2CPP / net6+**) with a strong protection stack, while **guaranteeing** the output still loads: every build is checked against MelonLoader's own `AssemblyVerifier` rules before it is accepted.

## Why "MelonLoader-friendly"?

On IL2CPP games MelonLoader loads mods through `AssemblyLoadContext` and runs them past `AssemblyVerifier`, which **rejects** an assembly unless:

1. it has exactly **one module**;
2. delegate types (`: MulticastDelegate`) have **no fields**;
3. every namespace / type name / method name is a **valid identifier**;
4. the **Shannon entropy** of all type + method name characters is in **`[4.0, 5.5]`**;
5. it can be fully read by **AsmResolver**, **Mono.Cecil** and the **CLR**.

Most obfuscators break rule 3 or 4 (they rename to `IlllIl` — too little entropy — or to weird Unicode), so their output is silently rejected. MelonFuscator's renamer is **entropy-aware** (uniform over a controlled alphabet, `entropy ≈ log2(alphabet)`), and the engine re-runs MelonLoader's exact verifier on the final file. If it would be rejected, MelonFuscator tells you instead of shipping a broken mod.

It also repairs the `typeof(Mod)` inside `MelonInfoAttribute` after renaming (that argument is stored as a **name string** in the blob, not a token — a classic reason renamed mods stop loading).

## Protections

| Protection | What it does |
|---|---|
| **Renamer** | Entropy-aware renaming of types/methods/fields/props/events; skips virtual overrides, Unity magic methods, P/Invoke, ctors, Harmony patch methods, and anything referenced by name in a string literal (reflection guard); repairs `System.Type` attribute args. Optional Unicode alphabet (`--unicode`). |
| **String Encryption** | Encrypts every `ldstr` (UTF-8 keystream), decrypted by an in-module method using only corlib types (portable Mono/CoreCLR). |
| **Proxy Calls** | Reroutes external static calls through generated proxies — breaks de4dot call-graph analysis. |
| **Control-Flow Flattening** | Splits each eligible method into basic blocks driven by a randomized `switch` dispatcher. Structuring decompilers (ICSharpCode/dnSpy/ILSpy) emit goto-soup or throw; the JIT runs it fine. On at `max` (`--flatten`). |
| **Control Flow** | Opaque predicates at method entry that decompilers cannot fold away. |
| **Anti-Debug (native)** | `Debugger.IsAttached`/`IsLogging`, `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` (ProcessDebugPort/ObjectHandle/Flags) and kernel-driver detection (TitanHide / Cheat Engine DBK / ScyllaHide). Wrapped in try/catch for non-Windows. |
| **Anti-Tamper** | Detects CLR profilers/instrumentation via their environment variables and terminates. |
| **Anti-Decompiler** | `SuppressIldasm` + decoy string-decryptor methods that poison de4dot's automatic string-decryptor detection. |
| **Watermark + Anti-de4dot** | `[module: MelonedBy("MelonFuscator.vX.Y.Z")]` + fake obfuscator-marker attributes (ConfusedBy, Dotfuscator, ...) to mislead de4dot. |

All anti-decompiler techniques keep the metadata **valid** (so MelonLoader still loads the mod); they make decompiled output useless rather than corrupting the image.

## Build

```
dotnet build -c Release
```

## Usage

```
MelonFuscator <input.dll> [options]

  -o, --output <path>    Output file (default: <input>.obf.dll)
  --preset <name>        light | melon | max        (default: melon)
  --seed <int>           Deterministic RNG seed
  --alphabet <int>       Rename alphabet size 16-45 (default: 32)
  --verbose              Verbose logging
  --no-verify            Skip the MelonLoader self-check
  --no-melon             Do not treat input as a MelonLoader mod

  Disable individual protections:
  --no-rename  --no-strings  --no-proxy  --no-flow
  --no-antidebug  --no-antitamper  --no-anti
```

Example:

```
MelonFuscator MyMod.dll --preset max --seed 1337
```

## Project layout

```
MelonFuscator.Engine    core obfuscation pipeline (AsmResolver-based)
MelonFuscator.Runtime   runtime templates (reserved for future cloned helpers)
MelonFuscator.CLI       command-line front end
samples/                a sample MelonLoader mod + shim for testing
```

## Disclaimer

For protecting your own MelonLoader mods and for authorized security research/education.
Do not use it to violate the terms of service of any software.
