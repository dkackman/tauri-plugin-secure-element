package net.kackman.secureelement

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Admits at most one authentication prompt at a time.
 *
 * androidx.biometric keeps a single client callback per Activity - each new
 * `BiometricPrompt` replaces it - and does not show a second prompt while one is
 * already up. A second request admitted while a prompt is showing would therefore
 * receive the first prompt's result, including its `CryptoObject`, and could sign
 * the wrong data with the wrong key. Callers take the slot before building a
 * prompt and give it back exactly once when that prompt's request settles.
 */
internal class AuthSlot {
    private val held = AtomicBoolean(false)

    /** Takes the slot if it is free; returns false if a prompt is already in flight. */
    fun tryAcquire(): Boolean = held.compareAndSet(false, true)

    /** Frees the slot. Releasing a slot that is not held has no effect. */
    fun release() {
        held.set(false)
    }
}
