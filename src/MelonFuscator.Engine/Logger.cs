namespace MelonFuscator.Engine;

/// <summary>Minimal colored console logger.</summary>
public sealed class Logger
{
    public bool Verbose { get; set; }

    private static void Write(string prefix, ConsoleColor color, string msg)
    {
        var old = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(prefix);
        Console.ForegroundColor = old;
        Console.WriteLine(msg);
    }

    public void Info(string msg) => Write("[*] ", ConsoleColor.Cyan, msg);
    public void Good(string msg) => Write("[+] ", ConsoleColor.Green, msg);
    public void Warn(string msg) => Write("[!] ", ConsoleColor.Yellow, msg);
    public void Error(string msg) => Write("[-] ", ConsoleColor.Red, msg);
    public void Step(string msg) => Write("  -> ", ConsoleColor.DarkGray, msg);
    public void Debug(string msg) { if (Verbose) Write("  .. ", ConsoleColor.DarkGray, msg); }
}
