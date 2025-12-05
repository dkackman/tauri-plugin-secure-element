package app.tauri.plugin.secureelement

import android.util.Log

class Plugin {
    fun pong(value: String): String {
        Log.i("Pong", value)
        return value
    }
}
