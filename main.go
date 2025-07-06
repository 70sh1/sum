package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/pflag"
	"github.com/zeebo/blake3"
	"github.com/zeebo/xxh3"

	"golang.org/x/crypto/blake2b"
)

const version = "0.3.0"

type mode = string

const (
	SHA256 mode = "sha256"
	SHA512 mode = "sha512"
	SHA1   mode = "sha1"

	SHA3_224 mode = "sha3-224"
	SHA3_256 mode = "sha3-256"
	SHA3_384 mode = "sha3-384"
	SHA3_512 mode = "sha3-512"

	BLAKE2B mode = "blake2b"
	BLAKE3  mode = "blake3" // ⚡

	CRC32 mode = "crc32"

	XXH3 mode = "xxh3" // ⚡⚡

	MD5 mode = "md5"
)

// Thread safe output
var (
	output = log.New(os.Stdout, "", 0)
	errout = log.New(os.Stderr, "", 0)
)

func main() {
	m := pflag.StringP("mode", "m", SHA256, modesUsage())
	u := pflag.BoolP("union", "u", false, "calculate union hash (a+b+c...) instead of individual files")
	key := pflag.StringP("hmac-key", "k", "", "switch to hmac mode and use the provided key")

	pflag.BoolFuncP("version", "v", "print current version and exit", func(s string) error {
		fmt.Println(version)
		os.Exit(0)
		return nil
	})

	// pflag.Usage = func() { errout.Println(pflag.CommandLine.FlagUsagesWrapped(5)) }
	pflag.Usage = func() {
		errout.Printf("Usage: %s [options] [paths]\nOptions:\n%s", os.Args[0], pflag.CommandLine.FlagUsages())
	}
	pflag.Parse()

	args := pflag.Args()
	if len(args) < 1 {
		pflag.Usage()
		os.Exit(1)
	}

	var paths []string
	var pathErrors []string
	for _, path := range args {
		path = filepath.Clean(path)
		globPaths, err := filepath.Glob(path)
		if err != nil {
			errout.Println(err)
		}
		if globPaths == nil {
			pathErrors = append(pathErrors, "file not found "+path)
			continue
		}
		for _, gp := range globPaths {
			if info, err := os.Stat(gp); err != nil || info.IsDir() {
				continue
			}
			paths = append(paths, gp)
		}
	}
	for _, e := range pathErrors {
		output.Println(e)
	}

	if len(paths) == 0 {
		return
	}

	if *u {
		sum, err := unionHash(paths, *m, *key)
		if err != nil {
			errout.Println(err)
			return
		}
		sumHex := hex.EncodeToString(sum)
		output.Printf("%s  (%d files)", sumHex, len(paths))
		return
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		sums = make([]string, len(paths))
	)
	wg.Add(len(paths))
	for i, path := range paths {
		go func() {
			defer wg.Done()
			sum, err := individualHash(path, *m, *key)
			if err != nil {
				errout.Println(err)
				return
			}
			sumHex := hex.EncodeToString(sum)

			mu.Lock()
			sums[i] = fmt.Sprintf("%s  %s", sumHex, filepath.Base(path))
			mu.Unlock()
		}()
	}
	wg.Wait()

	var result strings.Builder
	for i, s := range sums {
		result.WriteString(s)
		if i != len(sums)-1 {
			result.WriteString("\n")
		}
	}

	output.Println(result.String())
}

func individualHash(path string, m mode, key string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	h, err := newHash(m, key)
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(h, file); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func unionHash(paths []string, m mode, key string) ([]byte, error) {
	h, err := newHash(m, key)
	if err != nil {
		return nil, err
	}

	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		if _, err := io.Copy(h, file); err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}

func newHash(m mode, key string) (hash.Hash, error) {
	hmacKey := []byte(key)

	var h func() hash.Hash

	switch m {
	case SHA512:
		h = sha512.New
	case SHA256:
		h = sha256.New
	case SHA1:
		h = sha1.New

	case SHA3_224:
		h = func() hash.Hash { return sha3.New224() }
	case SHA3_256:
		h = func() hash.Hash { return sha3.New256() }
	case SHA3_384:
		h = func() hash.Hash { return sha3.New384() }
	case SHA3_512:
		h = func() hash.Hash { return sha3.New512() }

	case CRC32:
		h = func() hash.Hash { return crc32.NewIEEE() }

	case MD5:
		h = md5.New
	case BLAKE3:
		if hmacKey != nil {
			return blake3.NewKeyed(hmacKey)
		}
		return blake3.New(), nil
	case BLAKE2B:
		return blake2b.New(32, hmacKey)

	case XXH3:
		return xxh3.New(), nil

	default:
		return nil, fmt.Errorf("unknown mode: '%s'", m)
	}

	if hmacKey != nil {
		return hmac.New(h, hmacKey), nil
	}
	return h(), nil
}

func modesUsage() string {
	var result strings.Builder
	result.WriteString("specify hash function:")
	for _, s := range []mode{SHA256 + " (default)", SHA512, SHA1, SHA3_224, SHA3_256, SHA3_384, SHA3_512, BLAKE2B, BLAKE3, CRC32, XXH3, MD5} {
		result.WriteString("\n\t")
		result.WriteString(s)
	}
	return result.String()
}
