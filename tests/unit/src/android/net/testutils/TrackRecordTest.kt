/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net.testutils

import android.os.SystemClock
import com.android.testutils.ArrayTrackRecord
import com.android.testutils.TrackRecord
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import kotlin.system.measureTimeMillis
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

val TEST_VALUES = listOf(4, 13, 52, 94, 41, 68, 11, 13, 51, 0, 91, 94, 33, 98, 14)
const val ABSENT_VALUE = 2
// Caution in changing these : some tests rely on the fact that TEST_TIMEOUT > 2 * SHORT_TIMEOUT
// and LONG_TIMEOUT > 2 * TEST_TIMEOUT
const val SHORT_TIMEOUT = 40L // ms
const val TEST_TIMEOUT = 200L // ms
const val LONG_TIMEOUT = 5000L // ms

// The unit of time for interpreted tests
const val INTERPRET_TIME_UNIT = SHORT_TIMEOUT

@RunWith(JUnit4::class)
class TrackRecordTest {
    @Test
    fun testAddAndSizeAndGet() {
        val repeats = 22 // arbitrary
        val record = ArrayTrackRecord<Int>()
        assertEquals(0, record.size)
        repeat(repeats) { i -> record.add(i + 2) }
        assertEquals(repeats, record.size)
        record.add(2)
        assertEquals(repeats + 1, record.size)

        assertEquals(11, record[9])
        assertEquals(11, record.getOrNull(9))
        assertEquals(2, record[record.size - 1])
        assertEquals(2, record.getOrNull(record.size - 1))

        assertFailsWith<IndexOutOfBoundsException> { record[800] }
        assertFailsWith<IndexOutOfBoundsException> { record[-1] }
        assertFailsWith<IndexOutOfBoundsException> { record[repeats + 1] }
        assertNull(record.getOrNull(800))
        assertNull(record.getOrNull(-1))
        assertNull(record.getOrNull(repeats + 1))
        assertNull(record.getOrNull(800) { true })
        assertNull(record.getOrNull(-1) { true })
        assertNull(record.getOrNull(repeats + 1) { true })
    }

    @Test
    fun testIndexOf() {
        val record = ArrayTrackRecord<Int>()
        TEST_VALUES.forEach { record.add(it) }
        with(record) {
            assertEquals(9, indexOf(0))
            assertEquals(9, lastIndexOf(0))
            assertEquals(1, indexOf(13))
            assertEquals(7, lastIndexOf(13))
            assertEquals(3, indexOf(94))
            assertEquals(11, lastIndexOf(94))
            assertEquals(-1, indexOf(ABSENT_VALUE))
            assertEquals(-1, lastIndexOf(ABSENT_VALUE))
        }
    }

    @Test
    fun testContains() {
        val record = ArrayTrackRecord<Int>()
        TEST_VALUES.forEach { record.add(it) }
        TEST_VALUES.forEach { assertTrue(record.contains(it)) }
        assertFalse(record.contains(ABSENT_VALUE))
        assertTrue(record.containsAll(TEST_VALUES))
        assertTrue(record.containsAll(TEST_VALUES.sorted()))
        assertTrue(record.containsAll(TEST_VALUES.sortedDescending()))
        assertTrue(record.containsAll(TEST_VALUES.distinct()))
        assertTrue(record.containsAll(TEST_VALUES.subList(0, TEST_VALUES.size / 2)))
        assertTrue(record.containsAll(TEST_VALUES.subList(0, TEST_VALUES.size / 2).sorted()))
        assertTrue(record.containsAll(listOf()))
        assertFalse(record.containsAll(listOf(ABSENT_VALUE)))
        assertFalse(record.containsAll(TEST_VALUES + listOf(ABSENT_VALUE)))
    }

    @Test
    fun testEmpty() {
        val record = ArrayTrackRecord<Int>()
        assertTrue(record.isEmpty())
        record.add(1)
        assertFalse(record.isEmpty())
    }

    @Test
    fun testIterate() {
        val record = ArrayTrackRecord<Int>()
        record.forEach { fail("Expected nothing to iterate") }
        TEST_VALUES.forEach { record.add(it) }
        // zip relies on the iterator (this calls extension function Iterable#zip(Iterable))
        record.zip(TEST_VALUES).forEach { assertEquals(it.first, it.second) }
        // Also test reverse iteration (to test hasPrevious() and friends)
        record.reversed().zip(TEST_VALUES.reversed()).forEach { assertEquals(it.first, it.second) }
    }

    @Test
    fun testIteratorIsSnapshot() {
        val record = ArrayTrackRecord<Int>()
        TEST_VALUES.forEach { record.add(it) }
        val iterator = record.iterator()
        val expectedSize = record.size
        record.add(ABSENT_VALUE)
        record.add(ABSENT_VALUE)
        var measuredSize = 0
        iterator.forEach {
            ++measuredSize
            assertNotEquals(ABSENT_VALUE, it)
        }
        assertEquals(expectedSize, measuredSize)
    }

    @Test
    fun testSublist() {
        val record = ArrayTrackRecord<Int>()
        TEST_VALUES.forEach { record.add(it) }
        assertEquals(record.subList(3, record.size - 3),
                TEST_VALUES.subList(3, TEST_VALUES.size - 3))
    }

    fun testPollReturnsImmediately(record: TrackRecord<Int>) {
        record.add(4)
        val elapsed = measureTimeMillis { assertEquals(4, record.poll(LONG_TIMEOUT, 0)) }
        // Should not have waited at all, in fact.
        assertTrue(elapsed < LONG_TIMEOUT)
        record.add(7)
        record.add(9)
        // Can poll multiple times for the same position, in whatever order
        assertEquals(9, record.poll(0, 2))
        assertEquals(7, record.poll(Long.MAX_VALUE, 1))
        assertEquals(9, record.poll(0, 2))
        assertEquals(4, record.poll(0, 0))
        assertEquals(9, record.poll(0, 2) { it > 5 })
        assertEquals(7, record.poll(0, 0) { it > 5 })
    }

    @Test
    fun testPollReturnsImmediately() {
        testPollReturnsImmediately(ArrayTrackRecord())
        testPollReturnsImmediately(ArrayTrackRecord<Int>().newReadHead())
    }

    @Test
    fun testPollTimesOut() {
        val record = ArrayTrackRecord<Int>()
        var delay = measureTimeMillis { assertNull(record.poll(SHORT_TIMEOUT, 0)) }
        assertTrue(delay >= SHORT_TIMEOUT, "Delay $delay < $SHORT_TIMEOUT")
        delay = measureTimeMillis { assertNull(record.poll(SHORT_TIMEOUT, 0) { it < 10 }) }
        assertTrue(delay > SHORT_TIMEOUT)
    }

    @Test
    fun testPollWakesUp() {
        val record = ArrayTrackRecord<Int>()
        val barrier = CyclicBarrier(2)
        Thread {
            barrier.await(LONG_TIMEOUT, TimeUnit.MILLISECONDS) // barrier 1
            barrier.await() // barrier 2
            Thread.sleep(SHORT_TIMEOUT * 2)
            record.add(31)
        }.start()
        barrier.await() // barrier 1
        // Should find the element in more than SHORT_TIMEOUT but less than TEST_TIMEOUT
        var delay = measureTimeMillis {
            barrier.await() // barrier 2
            assertEquals(31, record.poll(TEST_TIMEOUT, 0))
        }
        assertTrue(delay in SHORT_TIMEOUT..TEST_TIMEOUT)
        // Polling for an element already added in anothe thread (pos 0) : should return immediately
        delay = measureTimeMillis { assertEquals(31, record.poll(TEST_TIMEOUT, 0)) }
        assertTrue(delay < TEST_TIMEOUT, "Delay $delay > $TEST_TIMEOUT")
        // Waiting for an element that never comes
        delay = measureTimeMillis { assertNull(record.poll(SHORT_TIMEOUT, 1)) }
        assertTrue(delay >= SHORT_TIMEOUT, "Delay $delay < $SHORT_TIMEOUT")
        // Polling for an element that doesn't match what is already there
        delay = measureTimeMillis { assertNull(record.poll(SHORT_TIMEOUT, 0) { it < 10 }) }
        assertTrue(delay > SHORT_TIMEOUT)
    }

    @Test
    fun testMultiplePoll() {
        interpretTestSpec(useReadHeads = false, spec = """
            add(4)         | poll(1, 0) = 4
                           | poll(0, 1) = null time 0..1
                           | poll(1, 1) = null time 1..2
            sleep; add(7)  | poll(2, 1) = 7 time 1..2
            sleep; add(18) | poll(2, 2) = 18 time 1..2
        """)
    }

    @Test
    fun testMultiplePollWithPredicate() {
        interpretTestSpec(useReadHeads = false, spec = """
                     | poll(1, 0) = null          | poll(1, 0) = null
            add(6)   | poll(1, 0) = 6             |
            add(11)  | poll(1, 0) { > 20 } = null | poll(1, 0) { = 11 } = 11
                     | poll(1, 0) { > 8 } = 11    |
        """)
    }

    @Test
    fun testMultipleReadHeads() {
        interpretTestSpec(useReadHeads = true, spec = """
                   | poll() = null | poll() = null | poll() = null
            add(5) |               | poll() = 5    |
                   | poll() = 5    |               |
            add(8) | poll() = 8    | poll() = 8    |
                   |               |               | poll() = 5
                   |               |               | poll() = 8
                   |               |               | poll() = null
                   |               | poll() = null |
        """)
    }

    /**
     * // TODO : don't submit without this.
     * Test poll()
     *   - Check that it immediately finds added stuff that matches
     * Test ReadHead#poll()
     *   - All of the above, and:
     *   - Put stuff, check that it timeouts when it doesn't match the predicate, and the read head
     *     has advanced
     *   - Check that it immediately advances the read head
     *   - Check multiple read heads in different threads
     * Test ReadHead#peek()
     */
}

/**
 * A small interpreter for testing parallel code. The interpreter will read a list of lines
 * consisting of "|"-separated statements. Each column runs in a different concurrent thread
 * and all threads wait for each other in between lines. Each statement is split on ";" then
 * matched with regular expressions in the instructionTable constant, which contains the
 * code associated with each statement.
 *
 * The time unit is defined in milliseconds by the INTERPRET_TIME_UNIT constant. Whitespace is
 * ignored. Quick ref of supported expressions :
 * sleep(x) : sleeps for x time units and returns Unit ; sleep alone means sleep(1)
 * add(x) : calls and returns TrackRecord#add.
 * poll(time, pos) [{ predicate }] : calls and returns TrackRecord#poll(x time units, pos).
 *   Optionally, a predicate may be specified.
 * poll() [{ predicate }] : calls and returns ReadHead#poll(1 time unit). Optionally, a predicate
 *   may be specified.
 * EXPR = VALUE : asserts that EXPR equals VALUE. EXPR is interpreted. VALUE can either be the
 *   string "null" or an int. Returns Unit.
 * EXPR time x..y : measures the time taken by EXPR and asserts it took at least x and at most
 *   y time units.
 * predicate must be one of "= x", "< x" or "> x".
 */
class SyntaxException(msg: String, cause: Throwable? = null) : RuntimeException(msg, cause)
class InterpretException(
    threadIndex: Int,
    lineNum: Int,
    className: String,
    methodName: String,
    fileName: String,
    cause: Throwable
) : RuntimeException(cause) {
    init {
        stackTrace = arrayOf(StackTraceElement(
                className,
                "$methodName:thread$threadIndex",
                fileName,
                lineNum)) + super.getStackTrace()
    }
}

// Some small helpers to avoid to say the large ".groupValues[index].trim()" every time
private fun MatchResult.strArg(index: Int) = this.groupValues[index].trim()
private fun MatchResult.intArg(index: Int) = strArg(index).toInt()
private fun MatchResult.timeArg(index: Int) = INTERPRET_TIME_UNIT * intArg(index)

// Parses a { = x } or { < x } or { > x } string and returns the corresponding predicate
// Returns an always-true predicate for empty and null arguments
private fun makePredicate(spec: String?): (Int) -> Boolean {
    if (spec.isNullOrEmpty()) return { true }
    val match = Regex("""\{\s*([<>=])\s*(\d+)\s*\}""").matchEntire(spec)
    if (null == match) throw SyntaxException("Predicate \"${spec}\"")
    val arg = match.intArg(2)
    return when (match.strArg(1)) {
        ">" -> { i -> i > arg }
        "<" -> { i -> i < arg }
        "=" -> { i -> i == arg }
        else -> throw RuntimeException("How did \"${spec}\" match this regexp ?")
    }
}

const val DEBUG_INTERPRETER = true

// The table contains pairs associating a regexp with the code to run. The statement is matched
// against each matcher in sequence and when a match is found the associated code is run, passing
// it the TrackRecord under test and the result of the regexp match.
typealias InterpretMatcher = Pair<Regex, (TrackRecord<Int>, MatchResult) -> Any?>

val interpretTable = listOf<InterpretMatcher>(
    // Interpret an empty line as doing nothing.
    Regex("") to { _, _ ->
        null
    },
    // Interpret "XXX time x..y" : run XXX and check it took at least x and not more than y
    Regex("""(.*)\s*time\s*(\d+)\.\.(\d+)""") to { t, r ->
        assertTrue(measureTimeMillis { interpret(r.strArg(1), t) } in r.timeArg(2)..r.timeArg(3))
    },
    // Interpret "XXX = YYY" : run XXX and assert its return value is equal to YYY. "null" supported
    Regex("""(.*)\s*=\s*(null|\d+)""") to { t, r ->
        interpret(r.strArg(1), t).also {
            if ("null" == r.strArg(2)) assertNull(it) else assertEquals(r.intArg(2), it)
        }
    },
    // Interpret sleep. Optional argument for the count, in INTERPRET_TIME_UNIT units.
    Regex("""sleep(\((\d+)\))?""") to { t, r ->
        SystemClock.sleep(if (r.strArg(2).isEmpty()) INTERPRET_TIME_UNIT else r.timeArg(2))
    },
    // Interpret "add(XXX)" as TrackRecord#add(int)
    Regex("""add\((\d+)\)""") to { t, r ->
        t.add(r.intArg(1))
    },
    // Interpret "poll(x, y)" as TrackRecord#poll(timeout = x * INTERPRET_TIME_UNIT, pos = y)
    // Accepts an optional {} argument for the predicate (see makePredicate for syntax)
    Regex("""poll\((\d+),\s*(\d+)\)\s*(\{.*\})?""") to { t, r ->
        t.poll(r.timeArg(1), r.intArg(2), makePredicate(r.strArg(3)))
    },
    // ReadHead#poll. If this throws in the cast, the code is malformed and has passed "poll()"
    // in a test that takes a TrackRecord that is not a ReadHead. It's technically possible to get
    // the test code to not compile instead of throw, but it's vastly more complex and this will
    // fail 100% at runtime any test that would not have compiled.
    Regex("""poll\(\)""") to { t, _ ->
        (t as ArrayTrackRecord<Int>.ReadHead).poll(INTERPRET_TIME_UNIT)
    }
)

// Split the line into multiple statements separated by ";" and execute them. Return whatever
// the last statement returned.
private fun <T : TrackRecord<Int>> interpretMultiple(instruction: String, r: T): Any? {
    return instruction.split(";").map { interpret(it.trim(), r) }.last()
}
// Match the statement to a regex and interpret it.
private fun <T : TrackRecord<Int>> interpret(instr: String, r: T): Any? {
    val (matcher, code) =
            interpretTable.find { instr matches it.first } ?: throw SyntaxException(instr)
    val match = matcher.matchEntire(instr) ?: throw SyntaxException(instr)
    return code(r, match)
}

// Create the ArrayTrackRecord<Int> under test, then spins as many threads as needed by the test
// spec and interpret each program concurrently, having all threads waiting on a CyclicBarrier
// after each line. If |useReadHeads| is true, it will create a ReadHead over the ArrayTrackRecord
// in each thread and call the interpreted methods on that ; if it's false, it will call the
// interpreted methods on the ArrayTrackRecord directly. Be careful that some instructions may
// only be supported on ReadHead, and will throw if called when using useReadHeads = false.
private fun interpretTestSpec(useReadHeads: Boolean, spec: String) {
    // For nice stack traces
    val callSite = getCallingMethod()
    val lines = spec.trim().trim('\n').split("\n").map { it.split("|") }
    // |threads| contains arrays of strings that make up the statements of a thread : in other
    // words, it's an array that contains a list of statements for each column in the spec.
    val threadCount = lines[0].size
    assertTrue(lines.all { it.size == threadCount })
    val threadInstructions = (0 until threadCount).map { i -> lines.map { it[i].trim() } }
    val barrier = CyclicBarrier(threadCount)
    val rec = ArrayTrackRecord<Int>()
    var crash: InterpretException? = null
    threadInstructions.mapIndexed { threadIndex, instructions ->
        Thread {
            val rh = if (useReadHeads) rec.newReadHead() else rec
            barrier.await()
            var lineNum = 0
            instructions.forEach {
                if (null != crash) return@Thread
                lineNum += 1
                try {
                    interpretMultiple(it, rh)
                } catch (e: Throwable) {
                    // If fail() or some exception was called, the thread will come here ; if the
                    // exception isn't caught the process will crash, which is not nice for testing.
                    // Instead, catch the exception, cancel other threads, and report nicely.
                    // Catch throwable because fail() is AssertionError, which inherits from Error.
                    crash = InterpretException(threadIndex, callSite.lineNumber + lineNum,
                            callSite.className, callSite.methodName, callSite.fileName, e)
                }
                barrier.await()
            }
        }.also { it.start() }
    }.forEach { it.join() }
    // If the test failed, crash with line number
    crash?.let { throw it }
}

private fun getCallingMethod(): StackTraceElement {
    try {
        throw RuntimeException()
    } catch (e: RuntimeException) {
        return e.stackTrace[3] // 0 is this method here, 1 is interpretTestSpec, 2 the lambda
    }
}
