package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zeebo/blake3"

	"golang.org/x/crypto/blake2b"
)

type mode string

const (
	SHA256  mode = "sha256"
	SHA512  mode = "sha512"
	BLAKE2B mode = "blake2b"
	BLAKE3  mode = "blake3" // ⚡
	SHA1    mode = "sha1"
	MD5     mode = "md5"
)

// Thread safe output
var (
	output = log.New(os.Stdout, "", 0)
	errout = log.New(os.Stderr, "", 0)
)

func main() {
	m := flag.String("m", string(SHA256), mUsage())
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}

	var wg sync.WaitGroup
	wg.Add(len(args))
	for _, path := range args {
		go func() {
			defer wg.Done()
			sum, err := calcHash(path, mode(*m))
			if err != nil {
				errout.Println(err)
				return
			}
			sumHex := hex.EncodeToString(sum)
			output.Println(sumHex, filepath.Base(path))
		}()
	}
	wg.Wait()
}

func calcHash(path string, mode mode) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hash hash.Hash
	switch mode {
	case SHA512:
		hash = sha512.New()
	case SHA256:
		hash = sha256.New()
	case SHA1:
		hash = sha1.New()
	case MD5:
		hash = md5.New()
	case BLAKE3:
		hash = blake3.New()
	case BLAKE2B:
		hash, err = blake2b.New(32, nil)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown mode: '%s'", mode)
	}

	if _, err := io.Copy(hash, file); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func mUsage() string {
	var result strings.Builder
	result.WriteString("specify hashing algorithm:")
	for _, s := range []string{"sha256 (default)", "sha512", "blake2b", "blake3", "sha1 (not recommended)", "md5 (not recommended)"} {
		result.WriteString("\n\t")
		result.WriteString(s)
	}
	return result.String()
}

func usage() {
	errout.Println()
	errout.Println("Arguments: [PATH]... Files to hash")
	errout.Println()
	errout.Println("OPTIONS:")
	output.Printf("  -m  %s \n", mUsage())
	errout.Println()
}
