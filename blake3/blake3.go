package blake3

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/bits"
	"unsafe"

	"github.com/zeebo/blake3/internal/alg"
	"github.com/zeebo/blake3/internal/consts"
	"github.com/zeebo/blake3/internal/utils"
)

//
// B3hasher contains state for a blake3 hash
//

type B3hasher struct {
	Len    uint64
	Chunks uint64
	Flags  uint32
	Key    [8]uint32
	Stack  Cvstack
	Buf    [8192]byte
}

func (a *B3hasher) reset() {
	a.Len = 0
	a.Chunks = 0
	a.Stack.Occ = 0
	a.Stack.Lvls = [8]uint8{}
	a.Stack.Bufn = 0
}

func (a *B3hasher) MarshalJSON() ([]byte, error) {
	// Buf is massive, but usually mostly trailing zeros
	// Omit trailing zeroes from marshaled field
	cpy := a.Buf
	trailZeroIdx := 0
	var bufStr string

	for i, v := range a.Buf {
		if v != 0 {
			trailZeroIdx = i + 1
		}
	}

	bufStr = base64.StdEncoding.EncodeToString(cpy[0:trailZeroIdx])

	return json.Marshal(map[string]interface{}{
		"Len":    a.Len,
		"Chunks": a.Chunks,
		"Flags":  a.Flags,
		"Key":    a.Key,
		"Stack":  a.Stack,
		"Buf":    bufStr,
	})
}

func (a *B3hasher) UnmarshalJSON(j []byte) error {
	// Re-add trailing zeroes to Buf when unmarshaling
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		fmt.Println(e)
		return e
	}

	var len uint64
	if e := json.Unmarshal(tmp["Len"], &len); e != nil {
		fmt.Println(e)
		return e
	}

	var chunks uint64
	if e := json.Unmarshal(tmp["Chunks"], &chunks); e != nil {
		fmt.Println(e)
		return e
	}

	var flags uint32
	if e := json.Unmarshal(tmp["Flags"], &flags); e != nil {
		fmt.Println(e)
		return e
	}

	var key [8]uint32
	if e := json.Unmarshal(tmp["Key"], &key); e != nil {
		fmt.Println(e)
		return e
	}

	var stack Cvstack
	if e := json.Unmarshal(tmp["Stack"], &stack); e != nil {
		fmt.Println(e)
		return e
	}

	// Zeroed array of 8192 bytes
	buf := [8192]byte{}
	var unmarshaledStr string
	var unmarshaledBuf []byte
	if e := json.Unmarshal(tmp["Buf"], &unmarshaledStr); e != nil {
		fmt.Println(e)
		return e
	}
	unmarshaledBuf, e := base64.StdEncoding.DecodeString(unmarshaledStr)
	if e != nil {
		fmt.Println(e)
		return e
	}
	// Replace leading bytes
	copy(buf[0:], unmarshaledBuf)

	a.Len = len
	a.Chunks = chunks
	a.Flags = flags
	a.Key = key
	a.Stack = stack
	a.Buf = buf
	return nil
}

// Comparison method for debugging marshaling
func (dst *B3hasher) compare(src *B3hasher) {
	if dst.Len != src.Len {
		fmt.Printf("B3hasher comparison failed: dst.Len %+v while src.Len %+v\n", dst.Len, src.Len)
	}

	if dst.Chunks != src.Chunks {
		fmt.Printf("B3hasher comparison failed: dst.Chunks %+v while src.Chunks %+v\n", dst.Chunks, src.Chunks)
	}

	if dst.Flags != src.Flags {
		fmt.Printf("B3hasher comparison failed: dst.Flags %+v while src.Flags %+v\n", dst.Flags, src.Flags)
	}

	if dst.Key != src.Key {
		fmt.Printf("B3hasher comparison failed: dst.Key %+v while src.Key %+v\n", dst.Key, src.Key)
	}

	if dst.Stack.Occ != src.Stack.Occ {
		fmt.Printf("B3hasher comparison failed: dst.Stack.Occ %+v while src.Stack.Occ %+v\n", dst.Stack.Occ, src.Stack.Occ)
	}

	if dst.Stack.Lvls != src.Stack.Lvls {
		fmt.Printf("B3hasher comparison failed: dst.Stack.Lvls %+v while src.Stack.Lvls %+v\n", dst.Stack.Lvls, src.Stack.Lvls)
	}

	if dst.Stack.Bufn != src.Stack.Bufn {
		fmt.Printf("B3hasher comparison failed: dst.Stack.Bufn %+v while src.Stack.Bufn %+v\n", dst.Stack.Bufn, src.Stack.Bufn)
	}

	if dst.Stack.Buf != src.Stack.Buf {
		fmt.Printf("B3hasher comparison failed: dst.Stack.Buf %+v while src.Stack.Buf %+v\n", dst.Stack.Buf, src.Stack.Buf)
	}

	if dst.Stack.Stack != src.Stack.Stack {
		fmt.Printf("B3hasher comparison failed: dst.Stack.Stack %+v while src.Stack.Stack %+v\n", dst.Stack.Stack, src.Stack.Stack)
	}

	if dst.Buf != src.Buf {
		fmt.Printf("B3hasher comparison failed: dst.Buf %+v while src.Buf %+v\n", dst.Buf, src.Buf)
	}
	return
}

func (a *B3hasher) update(buf []byte) {
	// relies on the first two words of a string being the same as a slice
	a.updateString(*(*string)(unsafe.Pointer(&buf)))
}

func (a *B3hasher) updateString(buf string) {
	var input *[8192]byte

	for len(buf) > 0 {
		if a.Len == 0 && len(buf) > 8192 {
			// relies on the data pointer being the first word in the string header
			input = (*[8192]byte)(*(*unsafe.Pointer)(unsafe.Pointer(&buf)))
			buf = buf[8192:]
		} else if a.Len < 8192 {
			n := copy(a.Buf[a.Len:], buf)
			a.Len += uint64(n)
			buf = buf[n:]
			continue
		} else {
			input = &a.Buf
		}

		a.consume(input)
		a.Len = 0
		a.Chunks += 8
	}
}

func (a *B3hasher) consume(input *[8192]byte) {
	var out ChainVector
	var chain [8]uint32
	alg.HashF(input, 8192, a.Chunks, a.Flags, &a.Key, &out, &chain)
	a.Stack.pushN(0, &out, 8, a.Flags, &a.Key)
}

func (a *B3hasher) finalize(p []byte) {
	var d Digest
	a.finalizeDigest(&d)
	_, _ = d.Read(p)
}

func (a *B3hasher) finalizeDigest(d *Digest) {
	if a.Chunks == 0 && a.Len <= consts.ChunkLen {
		compressAll(d, a.Buf[:a.Len], a.Flags, a.Key)
		return
	}

	d.chain = a.Key
	d.flags = a.Flags | consts.Flag_ChunkEnd

	if a.Len > 64 {
		var buf ChainVector
		alg.HashF(&a.Buf, a.Len, a.Chunks, a.Flags, &a.Key, &buf, &d.chain)

		if a.Len > consts.ChunkLen {
			complete := (a.Len - 1) / consts.ChunkLen
			a.Stack.pushN(0, &buf, int(complete), a.Flags, &a.Key)
			a.Chunks += complete
			a.Len = uint64(copy(a.Buf[:], a.Buf[complete*consts.ChunkLen:a.Len]))
		}
	}

	if a.Len <= 64 {
		d.flags |= consts.Flag_ChunkStart
	}

	d.counter = a.Chunks
	d.blen = uint32(a.Len) % 64

	base := a.Len / 64 * 64
	if a.Len > 0 && d.blen == 0 {
		d.blen = 64
		base -= 64
	}

	if consts.OptimizeLittleEndian {
		copy((*[64]byte)(unsafe.Pointer(&d.block[0]))[:], a.Buf[base:a.Len])
	} else {
		var tmp [64]byte
		copy(tmp[:], a.Buf[base:a.Len])
		utils.BytesToWords(&tmp, &d.block)
	}

	for a.Stack.Bufn > 0 {
		a.Stack.flush(a.Flags, &a.Key)
	}

	var tmp [16]uint32
	for Occ := a.Stack.Occ; Occ != 0; Occ &= Occ - 1 {
		col := uint(bits.TrailingZeros64(Occ)) % 64

		alg.Compress(&d.chain, &d.block, d.counter, d.blen, d.flags, &tmp)

		*(*[8]uint32)(unsafe.Pointer(&d.block[0])) = a.Stack.Stack[col]
		*(*[8]uint32)(unsafe.Pointer(&d.block[8])) = *(*[8]uint32)(unsafe.Pointer(&tmp[0]))

		if Occ == a.Stack.Occ {
			d.chain = a.Key
			d.counter = 0
			d.blen = consts.BlockLen
			d.flags = a.Flags | consts.Flag_Parent
		}
	}

	d.flags |= consts.Flag_Root
}

//
// chain value stack
//

type ChainVector = [64]uint32

type Cvstack struct {
	Occ   uint64   // which levels in stack are Occupied
	Lvls  [8]uint8 // what level the buf input was in
	Bufn  int      // how many pairs are loaded into buf
	Buf   [2]ChainVector
	Stack [64][8]uint32
}

func (a *Cvstack) pushN(l uint8, cv *ChainVector, n int, flags uint32, key *[8]uint32) {
	for i := 0; i < n; i++ {
		a.pushL(l, cv, i)
		for a.Bufn == 8 {
			a.flush(flags, key)
		}
	}
}

func (a *Cvstack) pushL(l uint8, cv *ChainVector, n int) {
	bit := uint64(1) << (l & 63)
	if a.Occ&bit == 0 {
		readChain(cv, n, &a.Stack[l&63])
		a.Occ ^= bit
		return
	}

	a.Lvls[a.Bufn&7] = l
	writeChain(&a.Stack[l&63], &a.Buf[0], a.Bufn)
	copyChain(cv, n, &a.Buf[1], a.Bufn)
	a.Bufn++
	a.Occ ^= bit
}

func (a *Cvstack) flush(flags uint32, key *[8]uint32) {
	var out ChainVector
	alg.HashP(&a.Buf[0], &a.Buf[1], flags|consts.Flag_Parent, key, &out, a.Bufn)

	Bufn, Lvls := a.Bufn, a.Lvls
	a.Bufn, a.Lvls = 0, [8]uint8{}

	for i := 0; i < Bufn; i++ {
		a.pushL(Lvls[i]+1, &out, i)
	}
}

//
// helpers to deal with reading/writing transposed values
//

func copyChain(in *ChainVector, icol int, out *ChainVector, ocol int) {
	type u = uintptr
	type p = unsafe.Pointer
	type a = *uint32

	i := p(u(p(in)) + u(icol*4))
	o := p(u(p(out)) + u(ocol*4))

	*a(p(u(o) + 0*32)) = *a(p(u(i) + 0*32))
	*a(p(u(o) + 1*32)) = *a(p(u(i) + 1*32))
	*a(p(u(o) + 2*32)) = *a(p(u(i) + 2*32))
	*a(p(u(o) + 3*32)) = *a(p(u(i) + 3*32))
	*a(p(u(o) + 4*32)) = *a(p(u(i) + 4*32))
	*a(p(u(o) + 5*32)) = *a(p(u(i) + 5*32))
	*a(p(u(o) + 6*32)) = *a(p(u(i) + 6*32))
	*a(p(u(o) + 7*32)) = *a(p(u(i) + 7*32))
}

func readChain(in *ChainVector, col int, out *[8]uint32) {
	type u = uintptr
	type p = unsafe.Pointer
	type a = *uint32

	i := p(u(p(in)) + u(col*4))

	out[0] = *a(p(u(i) + 0*32))
	out[1] = *a(p(u(i) + 1*32))
	out[2] = *a(p(u(i) + 2*32))
	out[3] = *a(p(u(i) + 3*32))
	out[4] = *a(p(u(i) + 4*32))
	out[5] = *a(p(u(i) + 5*32))
	out[6] = *a(p(u(i) + 6*32))
	out[7] = *a(p(u(i) + 7*32))
}

func writeChain(in *[8]uint32, out *ChainVector, col int) {
	type u = uintptr
	type p = unsafe.Pointer
	type a = *uint32

	o := p(u(p(out)) + u(col*4))

	*a(p(u(o) + 0*32)) = in[0]
	*a(p(u(o) + 1*32)) = in[1]
	*a(p(u(o) + 2*32)) = in[2]
	*a(p(u(o) + 3*32)) = in[3]
	*a(p(u(o) + 4*32)) = in[4]
	*a(p(u(o) + 5*32)) = in[5]
	*a(p(u(o) + 6*32)) = in[6]
	*a(p(u(o) + 7*32)) = in[7]
}

//
// compress <= chunkLen bytes in one shot
//

func compressAll(d *Digest, in []byte, flags uint32, key [8]uint32) {
	var compressed [16]uint32

	d.chain = key
	d.flags = flags | consts.Flag_ChunkStart

	for len(in) > 64 {
		buf := (*[64]byte)(unsafe.Pointer(&in[0]))

		var block *[16]uint32
		if consts.OptimizeLittleEndian {
			block = (*[16]uint32)(unsafe.Pointer(buf))
		} else {
			block = &d.block
			utils.BytesToWords(buf, block)
		}

		alg.Compress(&d.chain, block, 0, consts.BlockLen, d.flags, &compressed)

		d.chain = *(*[8]uint32)(unsafe.Pointer(&compressed[0]))
		d.flags &^= consts.Flag_ChunkStart

		in = in[64:]
	}

	if consts.OptimizeLittleEndian {
		copy((*[64]byte)(unsafe.Pointer(&d.block[0]))[:], in)
	} else {
		var tmp [64]byte
		copy(tmp[:], in)
		utils.BytesToWords(&tmp, &d.block)
	}

	d.blen = uint32(len(in))
	d.flags |= consts.Flag_ChunkEnd | consts.Flag_Root
}
