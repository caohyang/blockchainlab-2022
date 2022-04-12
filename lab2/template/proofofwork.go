package main

import (
	"strconv"
	"fmt"
	"bytes"
	"math"
	"math/big"
	"crypto/sha256"
)

var (
	maxNonce = math.MaxInt64
)

// ProofOfWork represents a proof-of-work
type ProofOfWork struct {
	block *Block
}

// NewProofOfWork builds and returns a ProofOfWork
func NewProofOfWork(b *Block) *ProofOfWork {
	pow := &ProofOfWork{b}

	return pow
}

// Run performs a proof-of-work
// implement
func (pow *ProofOfWork) Run() (int, []byte) {
	var buffer bytes.Buffer
	nonce := -1
	
	buffer.Write(pow.block.PrevBlockHash)
	
	hashdata := sha256.Sum256(NewMerkleTree(pow.block.Data).RootNode.Data) 
	buffer.Write(hashdata[:])
	
	buffer.Write([]byte(fmt.Sprintf("%X", pow.block.Timestamp)))
	buffer.Write([]byte(fmt.Sprintf("%X", pow.block.Bits)))
	commonhash := buffer.Bytes()
	
	for ; nonce < 0 || pow.Validate() == false ; {
		nonce += 1
		hexnonce := []byte(fmt.Sprintf("%X", nonce))

		buffer.Reset()
		buffer.Write(commonhash)
		buffer.Write(hexnonce)
		
		res := sha256.Sum256(buffer.Bytes())
		pow.block.Hash = res[:]
	}

	return nonce, pow.block.Hash
}

// Validate validates block's PoW
// implement
func (pow *ProofOfWork) Validate() bool {
	// https://my.oschina.net/robin3d/blog/1862766
	var buf bytes.Buffer
	for _, v := range pow.block.Hash {
		t := strconv.FormatInt(int64(v), 16)
		if len(t) > 1 {
			buf.WriteString(t)
		} else {
			buf.WriteString("0"+t)
		}
	}

	big1, _ := new(big.Int).SetString(buf.String(), 16)
	big2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(256-pow.block.Bits)), nil)

	result := big1.Cmp(big2)
	if result < 0 {
		return true
	} else {
		return false
	}
}