//go:build !riscv64
// +build !riscv64

package oracle

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var preimages = make(map[common.Hash][]byte)
var root = "/tmp/cannon"
var file *os.File

func SetupMemoryDataFile() {
	var err error
	file, err = os.OpenFile(fmt.Sprintf("%s/memory_data", root), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	file.Truncate(0)
	file.Seek(0, 0)
}

func CloseFile() {
	err := file.Close()
	if err != nil {
		panic(err)
	}
}

func SetRoot(newRoot string) {
	root = newRoot
	err := os.MkdirAll(root, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
}

// padOrTrim returns (size) bytes from input (bb)
// Short bb gets zeros padding at end, Long bb gets lsb bits trimmed
func padOrTrim(bb []byte, size int) []byte {
	l := len(bb)
	if l == size {
		return bb
	}
	if l > size {
		return bb[:size]
	}
	tmp := make([]byte, size)
	copy(tmp, bb)
	return tmp
}

func WriteInputHash(bs [32]byte) {
	file.Write(bs[:]) // write first inputhash
}

func Preimage(hash common.Hash) []byte {
	val, ok := preimages[hash]
	// key := fmt.Sprintf("%s/%s", root, hash)
	// We write the preimage even if its value is nil (will result in an empty file).
	// This can happen if the hash represents a full node that is the child of another full node
	// that collapses due to a key deletion. See fetching-preimages.md for more details.
	// err := ioutil.WriteFile(key, val, 0644)
	// check(err)
	if !ok {
		panic("preimage of key " + hash.String() + " must exist")
	}
	comphash := crypto.Keccak256Hash(val)
	if ok && hash != comphash {
		panic("corruption in hash " + hash.String())
	}

	bs := make([]byte, 8)
	binary.LittleEndian.PutUint64(bs, uint64(len(val)))
	fmt.Printf("write length %+v\n", binary.LittleEndian.Uint64(bs))
	file.Write(bs) // write length first
	// file.Write(val)
	valPadding := padOrTrim(val, (len(val)+7)&^0x7)
	os.Stderr.WriteString(fmt.Sprintf("input to compute hash %v\n", val))
	os.Stderr.WriteString(fmt.Sprintf("input to padding %v\n", valPadding))
	file.Write(valPadding) // then wrilte full value, round up to 8 multiple.
	// fmt.Println("why")
	return val
}

func Preimages() map[common.Hash][]byte {
	return preimages
}

// PreimageKeyValueWriter wraps the Put method of a backing data store.
type PreimageKeyValueWriter struct{}

// Put inserts the given value into the key-value data store.
func (kw PreimageKeyValueWriter) Put(key []byte, value []byte) error {
	hash := crypto.Keccak256Hash(value)
	if hash != common.BytesToHash(key) {
		panic("bad preimage value write")
	}
	preimages[hash] = common.CopyBytes(value)
	return nil
}

// Delete removes the key from the key-value data store.
func (kw PreimageKeyValueWriter) Delete(key []byte) error {
	return nil
}
