package com.android.testutils

// This function is private because the 2 is hardcoded here, and is not correct if not called
// directly from __LINE__ or __FILE__.
private fun callerStackTrace(): StackTraceElement = try {
    throw RuntimeException()
} catch (e: RuntimeException) {
    e.stackTrace[2] // 0 is here, 1 is get() in __FILE__ or __LINE__
}
val __FILE__: String get() = callerStackTrace().fileName
val __LINE__: Int get() = callerStackTrace().lineNumber
