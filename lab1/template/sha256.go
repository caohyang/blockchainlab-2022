package main

func putUint32(x []byte, s uint32) {
	x[0] = byte(s >> 24)
	x[1] = byte(s >> 16)
	x[2] = byte(s >> 8)
	x[3] = byte(s)
}

func mySha256(message []byte) [32]byte {
	//前八个素数平方根的小数部分的前面32位
	h0 := uint32(0x6a09e667)
	h1 := uint32(0xbb67ae85)
	h2 := uint32(0x3c6ef372)
	h3 := uint32(0xa54ff53a)
	h4 := uint32(0x510e527f)
	h5 := uint32(0x9b05688c)
	h6 := uint32(0x1f83d9ab)
	h7 := uint32(0x5be0cd19)

	//自然数中前面64个素数的立方根的小数部分的前32位
	k := [64]uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}

	mlen := len(message)
	padnum := 64 - (mlen-56+64)%64

	var pad byte
	for i := 0; i < padnum; i++ {
		if i == 0 {
			pad = 0x80
		} else {
			pad = 0
		}
		message = append(message, pad)
	}
	mlen <<= 3
	s := uint64(mlen)
	message = append(message, byte(s >> 56))
	message = append(message, byte(s >> 48))
	message = append(message, byte(s >> 40))
	message = append(message, byte(s >> 32))
	message = append(message, byte(s >> 24))
	message = append(message, byte(s >> 16))
	message = append(message, byte(s >> 8))
	message = append(message, byte(s))

	// reference: https://github.com/didianV5/blockchain/blob/master/encryption/sha256/source/sha256-source.go
	var w [64]uint32
	for len(message) >= 64 {
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(message[j])<<24 | uint32(message[j+1])<<16 | uint32(message[j+2])<<8 | uint32(message[j+3])
		}
		for i := 16; i < 64; i++ {
			v1 := w[i-2]
			t1 := (v1>>17 | v1<<(32-17)) ^ (v1>>19 | v1<<(32-19)) ^ (v1 >> 10)
			v2 := w[i-15]
			t2 := (v2>>7 | v2<<(32-7)) ^ (v2>>18 | v2<<(32-18)) ^ (v2 >> 3)
			w[i] = t1 + w[i-7] + t2 + w[i-16]
		}

		a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7

		for i := 0; i < 64; i++ {
			t1 := h + ((e>>6 | e<<(32-6)) ^ (e>>11 | e<<(32-11)) ^ (e>>25 | e<<(32-25))) + ((e & f) ^ (^e & g)) + k[i] + w[i]
			t2 := ((a>>2 | a<<(32-2)) ^ (a>>13 | a<<(32-13)) ^ (a>>22 | a<<(32-22))) + ((a & b) ^ (a & c) ^ (b & c))
			h = g
			g = f
			f = e
			e = d + t1
			d = c
			c = b
			b = a
			a = t1 + t2
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
		h5 += f
		h6 += g
		h7 += h

		message = message[64:]
	}
	
	sha256data := [32]byte{}
	putUint32(sha256data[0:], h0)
	putUint32(sha256data[4:], h1)
	putUint32(sha256data[8:], h2)
	putUint32(sha256data[12:], h3)
	putUint32(sha256data[16:], h4)
	putUint32(sha256data[20:], h5)
	putUint32(sha256data[24:], h6)
	putUint32(sha256data[28:], h7)
	
	return sha256data
}
