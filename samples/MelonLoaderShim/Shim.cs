using System;

// Minimal stand-in for MelonLoader's public surface, only enough to compile and test a mod.
// Mirrors the real namespace/type names so MelonFuscator's analyzer and verifier behave
// exactly as they would against the genuine MelonLoader.dll.
namespace MelonLoader
{
    [AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
    public class MelonInfoAttribute : Attribute
    {
        public MelonInfoAttribute(Type type, string name, string version, string author, string downloadLink = null) { }
    }

    [AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
    public class MelonGameAttribute : Attribute
    {
        public MelonGameAttribute(string developer = null, string name = null) { }
    }

    public abstract class MelonTypeBase
    {
        public virtual void OnInitializeMelon() { }
        public virtual void OnDeinitializeMelon() { }
        public virtual void OnUpdate() { }
        public virtual void OnLateUpdate() { }
        public virtual void OnGUI() { }
    }

    public abstract class MelonMod : MelonTypeBase { }
    public abstract class MelonPlugin : MelonTypeBase { }

    public static class MelonLogger
    {
        public static void Msg(string text) => Console.WriteLine("[Msg] " + text);
        public static void Warning(string text) => Console.WriteLine("[Warn] " + text);
        public static void Error(string text) => Console.WriteLine("[Error] " + text);
    }
}
