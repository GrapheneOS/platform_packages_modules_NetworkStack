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

import com.android.testutils.ArrayTrackRecord
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

val TEST_VALUES = listOf(4, 13, 52, 94, 41, 68, 11, 13, 51, 0, 91, 94, 33, 98, 14)
const val ABSENT_VALUE = 2

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

    /**
     * // TODO : add the following tests.
     * Test poll()
     *   - Put stuff, check that it's returned immediately
     *   - Check that it waits and times out
     *   - Check that it waits and finds the stuff added through the timeout
     *   - Put stuff, check that it's returned immediately when it matches the predicate
     *   - Check that it immediately finds added stuff that matches
     * Test ReadHead#poll()
     *   - All of the above, and:
     *   - Put stuff, check that it timeouts when it doesn't match the predicate, and the read head
     *     has advanced
     *   - Check that it immediately advances the read head
     * Test ReadHead#peek()
     */
}
