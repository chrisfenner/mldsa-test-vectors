package testvector

import (
	"bufio"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"iter"
	"strings"
)

// decodeHexAndCheckLength decodes a hex string and checks the length.
func decodeHexAndCheckLength(data string, expectedLength int) ([]byte, error) {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("decoding hex data: %d", err)
	}
	if len(decoded) != expectedLength {
		return nil, fmt.Errorf("unexpected data length %d", len(decoded))
	}
	return decoded, nil
}

// Algorithm 2, line 10 from FIPS 204:
// 𝑀′ ← BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
// Algorithm 6, line 9 from FIPS 204:
// 𝑡𝑟 ← H(𝑝𝑘, 64)
// Algorithm 7, line 6 from FIPS 204:
// µ = H(BytesToBits(𝑡𝑟)||𝑀′, 64)
func computeExternalMu(pk []byte, ctx []byte, msg []byte) ([]byte, error) {
	if len(ctx) > 255 {
		return nil, fmt.Errorf("ctx size too large: %d", len(ctx))
	}

	h := sha3.NewSHAKE256()
	// Compute tr from the hash of pk
	h.Write(pk)
	var tr [64]byte
	h.Read(tr[:])
	h.Reset()

	// Compute µ:
	// Feed in tr, then M' by parts
	h.Write(tr[:])
	binary.Write(h, binary.BigEndian, uint8(0))
	binary.Write(h, binary.BigEndian, uint8(len(ctx)))
	h.Write(ctx)
	h.Write(msg)
	var µ [64]byte
	h.Read(µ[:])

	return µ[:], nil
}

func getKeyValue(line string) (string, string, error) {
	splits := strings.Split(line, " = ")
	if len(splits) != 2 {
		return "", "", fmt.Errorf("encountered unexpected 'key = value' line %q", line)
	}
	return splits[0], splits[1], nil
}

func scanCase(scanner *bufio.Scanner) (map[string]string, error) {
	result := make(map[string]string)

	// Read "key = value" pairs until we encounter a key we've seen before.
	for {
		// Read the next line.
		line := scanner.Text()
		for line == "" {
			// Edge case: we need to initialize the scanner, or skip some empty lines.
			if !scanner.Scan() {
				err := scanner.Err()
				if err == nil {
					err = io.EOF
				}
				return nil, err
			}
			line = scanner.Text()
		}
		key, value, err := getKeyValue(line)
		if err != nil {
			return nil, err
		}
		// Reached a repeat. Return what we've got.
		if _, ok := result[key]; ok {
			return result, nil
		}

		// Add this line to the map and go to the next line.
		result[key] = value
		if !scanner.Scan() {
			break
		}
	}

	// Reached end of file. Return what we've got, unless we've got nothing, in which case return EOF.
	if len(result) == 0 {
		return nil, io.EOF
	}
	return result, nil
}

func katFromCaseData(data map[string]string) (*KATInput, error) {
	var result KATInput
	var ok bool
	result.Xi, ok = data["xi"]
	if !ok {
		return nil, fmt.Errorf("bad test case: no xi")
	}
	result.RNG, ok = data["rng"]
	if !ok {
		return nil, fmt.Errorf("bad test case: no rng")
	}
	result.PK, ok = data["pk"]
	if !ok {
		return nil, fmt.Errorf("bad test case: no pk")
	}
	result.SK, ok = data["sk"]
	if !ok {
		return nil, fmt.Errorf("bad test case: no sk")
	}
	result.Msg, ok = data["msg"]
	if !ok {
		return nil, fmt.Errorf("bad test case: no msg")
	}
	result.SM, ok = data["sm"]
	if !ok {
		return nil, fmt.Errorf("bad test case: no sm")
	}
	result.Ctx, ok = data["ctx"]
	if !ok {
		return nil, fmt.Errorf("bad test case: no ctx")
	}

	return &result, nil
}

// Returns an iterator of the known-answer tests from one of the _hedged_pure.rsp files.
// Returns nil, io.EOF at the end.
func StreamKATs(r io.Reader) (iter.Seq2[*KATInput, error], error) {
	scanner := bufio.NewScanner(r)

	return func(yield func(k *KATInput, e error) bool) {
		for {
			scanned, err := scanCase(scanner)
			if err != nil {
				yield(nil, fmt.Errorf("could not scan case data: %w", err))
				return
			}
			kat, err := katFromCaseData(scanned)
			if err != nil {
				yield(nil, fmt.Errorf("could not parse case data: %w", err))
				return
			}

			if !yield(kat, nil) {
				return
			}
		}
	}, nil
}
