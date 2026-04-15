package uuidv7

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// UUIDv7 格式 (RFC 9562):
//  48 bits : unix timestamp (毫秒)
//   4 bits : version (0111 = 7)
//  12 bits : rand_a
//   2 bits : variant (10)
//  62 bits : rand_b

var (
	mu        sync.Mutex
	lastMS    int64
	lastRandA uint16
)

// New 產生一個 UUIDv7 字串
func New() string {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now().UnixMilli()

	var randA uint16
	if now == lastMS {
		// 同一毫秒內遞增 rand_a 以保證單調性
		randA = lastRandA + 1
		if randA > 0x0FFF {
			// rand_a 溢位，等到下一毫秒
			for now <= lastMS {
				time.Sleep(100 * time.Microsecond)
				now = time.Now().UnixMilli()
			}
			randA = cryptoRand12()
		}
	} else {
		randA = cryptoRand12()
	}

	lastMS = now
	lastRandA = randA

	// 產生 8 bytes 隨機資料作為 rand_b (只用 62 bits)
	var rb [8]byte
	_, _ = rand.Read(rb[:])

	var uuid [16]byte

	// 48-bit timestamp (big-endian)
	uuid[0] = byte(now >> 40)
	uuid[1] = byte(now >> 32)
	uuid[2] = byte(now >> 24)
	uuid[3] = byte(now >> 16)
	uuid[4] = byte(now >> 8)
	uuid[5] = byte(now)

	// version (4 bits) + rand_a 高 4 bits
	uuid[6] = 0x70 | byte(randA>>8)
	// rand_a 低 8 bits
	uuid[7] = byte(randA)

	// variant (2 bits = 10) + rand_b 前 6 bits
	uuid[8] = 0x80 | (rb[0] & 0x3F)
	uuid[9] = rb[1]
	uuid[10] = rb[2]
	uuid[11] = rb[3]
	uuid[12] = rb[4]
	uuid[13] = rb[5]
	uuid[14] = rb[6]
	uuid[15] = rb[7]

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uint32(uuid[0])<<24|uint32(uuid[1])<<16|uint32(uuid[2])<<8|uint32(uuid[3]),
		uint16(uuid[4])<<8|uint16(uuid[5]),
		uint16(uuid[6])<<8|uint16(uuid[7]),
		uint16(uuid[8])<<8|uint16(uuid[9]),
		uint64(uuid[10])<<40|uint64(uuid[11])<<32|uint64(uuid[12])<<24|uint64(uuid[13])<<16|uint64(uuid[14])<<8|uint64(uuid[15]),
	)
}

// cryptoRand12 回傳 12-bit 隨機數
func cryptoRand12() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return (uint16(b[0])<<8 | uint16(b[1])) & 0x0FFF
}
