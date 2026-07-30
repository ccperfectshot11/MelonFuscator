using System;
using System.Collections.Generic;
using MelonLoader;

[assembly: MelonInfo(typeof(SampleMod.CoolMod), "CoolMod", "1.0.0", "TestAuthor")]
[assembly: MelonGame("SomeStudio", "SomeGame")]

namespace SampleMod
{
    // The main melon. Its virtual overrides (OnInitializeMelon/OnUpdate/...) must NOT be
    // renamed by the obfuscator, or MelonLoader would never call them.
    public class CoolMod : MelonMod
    {
        private int _counter;
        private readonly List<string> _log = new List<string>();

        public override void OnInitializeMelon()
        {
            MelonLogger.Msg("CoolMod initializing - secret string one");
            _counter = ComputeSeed("hello world", 42);
            Greet("player");
        }

        public override void OnUpdate()
        {
            _counter++;
            if (_counter % 600 == 0)
                MelonLogger.Msg("Tick number " + _counter + " reached the threshold!");
        }

        // Private helper - should be renamed and its strings encrypted.
        private int ComputeSeed(string input, int salt)
        {
            int acc = salt;
            foreach (char c in input)
                acc = (acc * 31) + c;
            _log.Add("seed computed for: " + input);
            return acc;
        }

        private void Greet(string who)
        {
            var message = string.Format("Welcome, {0}! Enjoy the game.", who);
            MelonLogger.Warning(message);
            Helper.DoWork(message, _counter);
        }
    }

    // A second type to give the entropy check enough symbols to run.
    internal static class Helper
    {
        public static string Prefix = "internal-prefix";

        public static void DoWork(string data, int number)
        {
            var combined = Transform(data) + ":" + number.ToString();
            MelonLogger.Msg(combined);
        }

        private static string Transform(string s)
        {
            var result = "";
            foreach (var ch in s)
                result += (char)(ch ^ 1);
            return result;
        }
    }

    // A small data holder with several members.
    public class Payload
    {
        public string Name { get; set; } = "default-name";
        public int Value { get; set; }
        public bool Enabled { get; set; }

        public string Describe() => $"{Name}={Value} enabled={Enabled}";
        public void Reset() { Name = "reset"; Value = 0; Enabled = false; }
    }
}
