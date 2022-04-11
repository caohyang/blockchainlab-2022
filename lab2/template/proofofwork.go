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
	
	// hashdata: []byte
	hashdata := bytes.Join(pow.block.Data, []byte(""))  
	hashdata = append(hashdata, pow.block.PrevBlockHash)
	
	var final_hashdata []byte 
	for ; nonce < 0 || Validate(pow) == false ; {
		nonce += 1
		hexnonce := IntToHex(nonce)
		final_hashdata = append(hashdata, hexnonce)
		pow.block.Hash = sha256.Sum256(final_hashdata)
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
