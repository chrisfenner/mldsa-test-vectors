// Package main implements the entry logic for the 'testvectorconverter' tool.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/chrisfenner/mldsa-test-vectors/pkg/testvector"
)

var (
	filePath = flag.String("path", "", "path to a _hedged_pure test case from post-quantum-cryptography/KAT")
)

func main() {
	if err := mainErr(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func mainErr() error {
	flag.Parse()

	if *filePath == "" {
		return errors.New("no --path provided. Please provide a file path using --path.")
	}
	f, err := os.Open(*filePath)
	if err != nil {
		return fmt.Errorf("could not open %q: %v", *filePath, err)
	}

	kats, err := testvector.StreamKATs(f)
	if err != nil {
		return fmt.Errorf("could not start iterating test cases from %q: %v", *filePath, err)
	}

	var vectors []testvector.TestVector

	for kat, err := range kats {
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("could not iterate test cases from %q: %v", *filePath, err)
		}

		vector, err := testvector.ComputeTestVector(*kat)
		if err != nil {
			return fmt.Errorf("could not convert test vector: %v", err)
		}

		vectors = append(vectors, *vector)
	}

	output, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		return fmt.Errorf("could not convert to JSON: %v", err)
	}

	fmt.Println(string(output))
	return nil
}
