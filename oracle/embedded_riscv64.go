//go:build riscv64
// +build riscv64

package oracle

import (
	"fmt"
	"math/big"
	"os"
	"reflect"
	"unsafe"

	"encoding/binary"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"strconv"
)

var read_pointer_addr = uint64(0x100000000000)
var preimages = make(map[common.Hash][]byte)

var output_addr = uint64(0xf00000000000)

func byteAt(addr uint64, length int) []byte {
	var ret []byte
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&ret))
	bh.Data = uintptr(addr)
	bh.Len = length
	bh.Cap = length
	return ret
}

// input hash is in first 32 bytes
func InputHash() common.Hash {
	ret := byteAt(read_pointer_addr, 0x20)
	os.Stderr.WriteString("********* on chain starts here *********\n")
	hash := common.BytesToHash(ret)
	os.Stderr.WriteString(fmt.Sprintf("********* get inputhash ********* %x\n", hash))
	read_pointer_addr += 0x20
	return hash
}

func Halt() {
	//os.Stderr.WriteString("THIS SHOULD BE PATCHED OUT\n")
	// the exit syscall is a jump to 0x5ead0000 now
	os.Exit(0)
}

func Output(output common.Hash, receipts common.Hash) {
	ret := byteAt(output_addr, 0x20)
	copy(ret, output.Bytes())
	rret := byteAt(output_addr+0x20, 0x20)
	copy(rret, receipts.Bytes())
	Halt()
}

// preimage flow
func Preimage(hash common.Hash) []byte {
	os.Stderr.WriteString("********* start Preimage *********\n")
	if preimages == nil {
		os.Stderr.WriteString("allocate preimage map, NOTES: global var not take effect\n")
		preimages = make(map[common.Hash][]byte)
	}
	val, ok := preimages[hash]
	if !ok {
		os.Stderr.WriteString("get preimage from read pointer addr\n")
		size := binary.LittleEndian.Uint64(common.CopyBytes(byteAt(read_pointer_addr, 8)))

		// The preimage was recorded but is empty. This should mean the hash represents a full node
		// to be moved as part of a key deletion, when collapsing another full node which has only
		// one child left (the full node represent by the hash) due to the deletion.
		// In this case we return nil — the hash resolution call from the full node collapse case
		// will ignore the error and assume the node is a full node.
		// See fetching-preimages.md for more details.
		if size == 0 {
			preimages[hash] = nil
			return nil
		}
		read_pointer_addr += 8

		os.Stderr.WriteString("start reading size " + strconv.Itoa(int(size)))
		roundSize := (size + 7) &^ 0x7 // round read up to 8 multiples
		ret := common.CopyBytes(byteAt(read_pointer_addr, int(roundSize)))
		read_pointer_addr += uint64(roundSize) // to assure addr always round to 8 multiples, avoid unaligned error
		ret = ret[:size]                       // trim and get real bytes
		os.Stderr.WriteString("end reading size\n")

		os.Stderr.WriteString("start compute hash\n")
		// this is 20% of the exec instructions, this speedup is always an option
		// however, this step is important for zk proof to trust outside memory in simpler way
		realhash := crypto.Keccak256Hash(ret)
		os.Stderr.WriteString(fmt.Sprintf("input to compute hash %v\n", ret))
		os.Stderr.WriteString("end compute hash\n")
		if realhash != hash {
			os.Stderr.WriteString(fmt.Sprintf("hash mismatch, realhash %x desired hash %x\n", realhash, hash))
			panic("preimage has wrong hash")
		}
		preimages[hash] = ret
		os.Stderr.WriteString("set preimage\n")
		return ret
	}
	return val
}

// these are stubs in embedded world
func SetNodeUrl(newNodeUrl string)                                                        {}
func SetRoot(newRoot string)                                                              {}
func PrefetchStorage(*big.Int, common.Address, common.Hash, func(map[common.Hash][]byte)) {}
func PrefetchAccount(*big.Int, common.Address, func(map[common.Hash][]byte))              {}
func PrefetchCode(blockNumber *big.Int, addrHash common.Hash)                             {}
func PrefetchBlock(blockNumber *big.Int, startBlock bool, hasher types.TrieHasher)        {}

func SetupMemoryDataFile()       {}
func CloseFile()                 {}
func WriteInputHash(bs [32]byte) {}

// KeyValueWriter wraps the Put method of a backing data store.
type PreimageKeyValueWriter struct{}

func (kw PreimageKeyValueWriter) Put(key []byte, value []byte) error { return nil }
func (kw PreimageKeyValueWriter) Delete(key []byte) error            { return nil }
