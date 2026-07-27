# Tauri's command dispatch reflects over @Command-annotated methods and
# Jackson field-reflects over @InvokeArg-annotated classes. tauri-android's own
# consumer rules already keep these transitively, but keep this module's
# classes here too in case it's ever consumed without that propagation.
-keep class net.kackman.secureelement.SecureKeysPlugin {
    public <init>(...);
    @app.tauri.annotation.Command public <methods>;
}
-keep @app.tauri.annotation.InvokeArg class net.kackman.secureelement.** { *; }
