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
	"github.com/zeebo/xxh3"

	"golang.org/x/crypto/blake2b"
)

const version = "0.3.0"

type mode = string

const (
	SHA256  mode = "sha256"
	SHA512  mode = "sha512"
	SHA1    mode = "sha1"
	BLAKE2B mode = "blake2b"
	BLAKE3  mode = "blake3" // ⚡
	XXH3    mode = "xxh3"   // ⚡
	MD5     mode = "md5"
)

// Thread safe output
var (
	output = log.New(os.Stdout, "", 0)
	errout = log.New(os.Stderr, "", 0)
)

func main() {
	m := flag.String("m", string(SHA256), mUsage())
	u := flag.Bool("u", false, uUsage())

	flag.BoolFunc("v", vUsage(), func(s string) error {
		fmt.Println(version)
		os.Exit(0)
		return nil
	})
	flag.Usage = usage

	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		usage()
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
		sum, err := unionHash(paths, *m)
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
			sum, err := individualHash(path, *m)
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

func individualHash(path string, m mode) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	h, err := getHashFunction(m)
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(h, file); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func unionHash(paths []string, m mode) ([]byte, error) {
	h, err := getHashFunction(m)
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

func getHashFunction(m mode) (hash.Hash, error) {
	switch m {
	case SHA512:
		return sha512.New(), nil
	case SHA256:
		return sha256.New(), nil
	case SHA1:
		return sha1.New(), nil
	case MD5:
		return md5.New(), nil
	case BLAKE3:
		return blake3.New(), nil
	case BLAKE2B:
		return blake2b.New(32, nil)
	case XXH3:
		return xxh3.New(), nil

	default:
		return nil, fmt.Errorf("unknown mode: '%s'", m)
	}
}

func mUsage() string {
	var result strings.Builder
	result.WriteString("specify hash function:")
	for _, s := range []mode{SHA256 + " (default)", SHA512, SHA1, BLAKE2B, BLAKE3, XXH3, MD5} {
		result.WriteString("\n\t")
		result.WriteString(s)
	}
	return result.String()
}

func uUsage() string {
	return "calculate union hash (a+b+c...) instead of individual files"
}

func vUsage() string {
	return "print current version and exit"
}

func usage() {
	errout.Printf(`
Arguments: [PATH]... Files to hash
	
Options:
  -m  %s

  -u  %s

  -v  %s

`,
		mUsage(), uUsage(), vUsage())
}
