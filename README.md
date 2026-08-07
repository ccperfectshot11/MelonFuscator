# MelonFuscator

An aggressive, **MelonLoader-friendly** .NET obfuscator.

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
| **DynCipher** | A fresh random reversible byte cipher (XOR/ADD op-chain + keystream) generated **per build**, so no two outputs share a decryptor and no generic automated deobfuscator can hard-code the algorithm. Drives string + constant encryption. |
| **String Encryption** | Encrypts every `ldstr` (UTF-8, per-build DynCipher), decrypted by an in-module method using only corlib types (portable Mono/CoreCLR). |
| **Constant Encryption** | Non-trivial `ldc.i4` integer literals are replaced with an encrypted value + a call to an in-module decoder (per-build cipher). |
| **MBA Mutation** | Rewrites 32-bit integer arithmetic (`+ - & \| ^`) into algebraically identical **Mixed Boolean-Arithmetic** expressions, e.g. `a + b` → `(a ^ b) + 2·(a & b)`, with a random identity per site per build. The value is bit-for-bit unchanged; the decompiled output is tangled arithmetic that pattern cleaners (de4dot) no longer recognise. A sound stack-type analyzer guarantees only provably-int32 ops are touched. |
| **Data Encoding** | Every eligible 32-bit integer local is kept in memory **XOR-encoded** with a per-local key: each store writes `value ^ K`, each load decodes it. The real value only ever exists briefly on the stack, so a memory watch/dump shows scrambled data. Lossless and behavior-preserving (skips locals whose address is taken). |
| **Integrity Check** | Embeds the final type count and verifies it at runtime via reflection; a deobfuscator that strips types trips it. **Fail-open** (wrapped in try/catch, only reacts when it can positively confirm types were removed) so it never false-positives on a legit IL2CPP mod. |
| **Proxy Calls** | Reroutes external static calls through generated proxies that forward via `ldftn` + **`calli`** (a function-pointer indirection, not a direct call edge), and reroutes static field **reads** through generated accessor methods. Hides the call/field graph and breaks de4dot's forwarder remover. |
| **Control-Flow Flattening** | Splits methods into basic blocks driven by a randomized `switch` dispatcher whose state is XORed with a runtime-seeded field, so decompilers emit goto-soup or throw while the JIT runs it fine. Handles blocks that leave values on the stack (ternary / short-circuit) via **stack-spilling**, supports `switch`, and flattens **inside `try` / `catch` / `finally` bodies** (each self-contained region independently, preserving exception semantics). Anything not provably safe is left untouched. On at `max` (`--flatten`). |
| **Control Flow** | Opaque predicates at every method entry, seeded at load time from `Environment.TickCount` and built as identities true for **any** integer (e.g. `(x \| 1) != 0`, "`x·(x+1)` is even"), so a decompiler cannot fold them away or prove the branch is dead. |
| **Anti-Debug (native)** | `Debugger.IsAttached`/`IsLogging`, `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` (ProcessDebugPort/ObjectHandle/Flags) and kernel-driver detection (TitanHide / Cheat Engine DBK / ScyllaHide). Wrapped in try/catch for non-Windows. |
| **Anti-Tamper** | Detects CLR profilers/instrumentation via their environment variables and terminates. |
| **Anti-Decompiler** | `SuppressIldasm` + decoy string-decryptor methods that poison de4dot's automatic string-decryptor detection. |
| **Decompiler Bomb** | Never-called methods containing a huge deeply-nested expression tree. The CLR never JITs them (and they're valid IL anyway), but a structuring decompiler recurses on the AST and **StackOverflows** — crashing dnSpy/ILSpy when the type is opened. On at `max` (`--no-bomb` to disable). |
| **Watermark + Anti-de4dot** | `[module: MelonedBy("MelonFuscator.vX.Y.Z")]` + fake obfuscator-marker attributes (ConfusedBy, Dotfuscator, ...) to mislead de4dot. |

All anti-decompiler techniques keep the metadata **valid** (so MelonLoader still loads the mod); they make decompiled output useless rather than corrupting the image.

### Coroutine / async safety

Every protection that rewrites method bodies (MBA, data encoding, constant encryption, call/field proxying, control-flow flattening, opaque predicates) **skips compiler-generated state machines** — the nested types C# emits for iterators (`yield return`, Unity coroutines) and `async` methods. Those resume by switching on a hidden `<>1__state` field into the middle of `MoveNext`, an implicit protocol structural rewrites can't see; touching them produces IL that verifies but throws `InvalidProgramException` the moment the JIT runs the coroutine. MelonFuscator detects them by **implemented interface** (`IEnumerator` / `IAsyncStateMachine`), so the guard survives renaming and holds regardless of the type's name.

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

  --flatten / --no-flatten   Control-flow flattening (on at 'max')
  --unicode                  Unicode rename alphabet (experimental)

  Disable individual protections:
  --no-rename  --no-strings  --no-constants  --no-mutate  --no-encode  --no-proxy  --no-flow
  --no-antidebug  --no-antitamper  --no-anti  --no-bomb
```

Example:

```
MelonFuscator MyMod.dll --preset max --seed 1337
```

## Project layout

```
MelonFuscator.Engine    core obfuscation pipeline (AsmResolver-based)
MelonFuscator.Runtime   runtime templates (reserved for future cloned helpers)
MelonFuscator.CLI       command-line front end (MelonFuscator.CLI.exe)
MelonFuscator.GUI       WPF desktop front end (MelonFuscator.GUI.exe)
```

## License

Source-available under the **MelonFuscator License** (see [LICENSE](LICENSE)).

You may freely use and modify it to protect **your own** mods/software. You may **not**
use it to deobfuscate, reverse-engineer, crack, or circumvent protections on any software
you do not own or are not authorized to modify. Distributed forks must stay source-available
under the same license with attribution.

## Disclaimer

For protecting your own MelonLoader mods and for authorized security research/education.
Do not use it to violate the terms of service of any software.
