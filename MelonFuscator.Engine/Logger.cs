namespace MelonFuscator.Engine;

/// <summary>Minimal colored logger. Writes to the console, or to a sink (e.g. a GUI) when set.</summary>
public sealed class Logger
{
    public bool Verbose { get; set; }

    /// <summary>When set, messages go here instead of the console (level, text).</summary>
    public Action<LogLevel, string>? Sink { get; set; }

    private void Write(string prefix, ConsoleColor color, LogLevel level, string msg)
    {
        if (Sink != null)
        {
            Sink(level, prefix + msg);
            return;
        }
        var old = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(prefix);
        Console.ForegroundColor = old;
        Console.WriteLine(msg);
    }

    public void Info(string msg) => Write("[*] ", ConsoleColor.Cyan, LogLevel.Info, msg);
    public void Good(string msg) => Write("[+] ", ConsoleColor.Green, LogLevel.Good, msg);
    public void Warn(string msg) => Write("[!] ", ConsoleColor.Yellow, LogLevel.Warn, msg);
    public void Error(string msg) => Write("[-] ", ConsoleColor.Red, LogLevel.Error, msg);
    public void Step(string msg) => Write("  -> ", ConsoleColor.DarkGray, LogLevel.Step, msg);
    public void Debug(string msg) { if (Verbose) Write("  .. ", ConsoleColor.DarkGray, LogLevel.Step, msg); }
}

public enum LogLevel { Info, Good, Warn, Error, Step }
