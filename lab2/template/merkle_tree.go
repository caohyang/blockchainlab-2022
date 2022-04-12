package main
import (
	"bytes"
	"crypto/sha256"
)

// MerkleTree represent a Merkle tree
type MerkleTree struct {
	RootNode *MerkleNode
}

// MerkleNode represent a Merkle tree node
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

// NewMerkleTree creates a new Merkle tree from a sequence of data
// implement
func NewMerkleTree(data [][]byte) *MerkleTree {
	// var node = MerkleNode{nil, nil, data[0]}
	// var mTree = MerkleTree{&node}
	
	num := len(data)
	node := make([]*MerkleNode, 3*num)
	
	for i:=0; i<num; i++ {
		node[i] = NewMerkleNode(nil, nil, data[i])
	}
	if num%2 == 1 {
		node[num] = NewMerkleNode(nil, nil, data[num-1])
		num ++
	}
	
	pleft := 0
	pright := num-1
	pcur := num
	for ;pleft != pright; {
		for ; ; {
			if pleft == pright {
				node[pcur] = NewMerkleNode(nil, node[pleft], nil)
				pcur ++
				pleft ++
				break
			} else {
				node[pcur] = NewMerkleNode(node[pleft], node[pleft+1], nil)
				pcur ++
				pleft += 2
				if pleft > pright {
					break
				}
			}
		}
		pright = pcur -1
	}
	pcur --
	var mTree = MerkleTree{node[pcur]}
	return &mTree
}

// NewMerkleNode creates a new Merkle tree node
// implement
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	node := MerkleNode{}
	node.Left = left
	node.Right = right
	var hash [32]byte 
	if node.Left == nil {
		if node.Right == nil {
			hash = sha256.Sum256(data)
		} else{
			hash = sha256.Sum256(right.Data)
		}
	} else {
		var buffer bytes.Buffer 
  		buffer.Write(left.Data)
		buffer.Write(right.Data)
		hash = sha256.Sum256(buffer.Bytes())
	}
	node.Data = hash[:]
	return &node
}
