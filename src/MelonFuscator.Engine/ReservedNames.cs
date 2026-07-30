namespace MelonFuscator.Engine;

/// <summary>
/// Names that must NOT be renamed because they are invoked "by name" by the Unity
/// engine or by MelonLoader (not through the vtable). Renaming them still compiles
/// but the code is no longer called at runtime.
/// </summary>
public static class ReservedNames
{
    // Unity MonoBehaviour "magic" methods. They are not virtual, so the
    // "skip virtual methods" rule does not cover them - list them here.
    public static readonly HashSet<string> UnityMagicMethods = new(StringComparer.Ordinal)
    {
        "Awake", "Start", "OnEnable", "OnDisable", "OnDestroy",
        "Update", "FixedUpdate", "LateUpdate",
        "OnGUI", "OnApplicationQuit", "OnApplicationFocus", "OnApplicationPause",
        "OnBecameVisible", "OnBecameInvisible",
        "OnPreCull", "OnPreRender", "OnPostRender", "OnRenderObject", "OnRenderImage",
        "OnDrawGizmos", "OnDrawGizmosSelected", "OnValidate", "Reset",
        "OnCollisionEnter", "OnCollisionStay", "OnCollisionExit",
        "OnCollisionEnter2D", "OnCollisionStay2D", "OnCollisionExit2D",
        "OnTriggerEnter", "OnTriggerStay", "OnTriggerExit",
        "OnTriggerEnter2D", "OnTriggerStay2D", "OnTriggerExit2D",
        "OnMouseDown", "OnMouseUp", "OnMouseEnter", "OnMouseExit", "OnMouseOver",
        "OnMouseDrag", "OnMouseUpAsButton",
        "OnLevelWasLoaded", "OnParticleCollision", "OnParticleTrigger",
        "OnAnimatorMove", "OnAnimatorIK",
        "OnAudioFilterRead", "OnConnectedToServer", "OnServerInitialized",
        "OnJointBreak", "OnControllerColliderHit",
        "OnTransformChildrenChanged", "OnTransformParentChanged",
    };

    // Unity/IL2CPP base types recognized by name (inheriting from them = handle with care).
    public static readonly HashSet<string> UnityBaseTypeNames = new(StringComparer.Ordinal)
    {
        "MonoBehaviour", "ScriptableObject", "Behaviour", "Component", "Object"
    };

    // HarmonyLib discovers these patch-class methods by NAME convention (when they have no
    // explicit [HarmonyPrefix]/[HarmonyPostfix]/... attribute). Renaming them silently
    // disables the patch, so we never rename a method with one of these names.
    public static readonly HashSet<string> HarmonyConventionMethods = new(StringComparer.Ordinal)
    {
        "Prefix", "Postfix", "Transpiler", "Finalizer", "Prepare",
        "Cleanup", "TargetMethod", "TargetMethods", "ReversePatch",
    };
}
