package main

import (
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
	nonce := -1

	var buffer bytes.Buffer
	// hashdata: []byte
	hashdata := bytes.Join(pow.block.Data, []byte(""))  
	buffer.Write(hashdata)
	buffer.Write(pow.block.PrevBlockHash)
	hashdata = buffer.Bytes()
	
	for ; nonce < 0 || Validate(pow) == false ; {
		nonce += 1
		hexnonce := IntToHex(Int64(nonce))

		buffer.Reset()
		buffer.Write(hashdata)
		buffer.Write(hexnonce)
		
		res := sha256.Sum256(buffer.Bytes())
		pow.block.Hash = res[:]
	}

	return nonce, pow.block.Hash
}

// Validate validates block's PoW
// implement
func (pow *ProofOfWork) Validate() bool {
	big1 := new(big.Int).SetString(pow.block.Hash, 16)
	big2 := big.NewInt(1<<(256-pow.block.Bits))
	result := big1.cmp(big2)
	if result < 0 {
		return true
	} else {
		return false
	}
}