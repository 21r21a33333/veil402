package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/consensys/gnark/logger"
)

func main() {
	logger.Disable()
	artifacts := flag.String("artifacts", "", "path to a versioned Veil artifact bundle")
	flag.Parse()
	if *artifacts == "" {
		fmt.Fprintln(os.Stderr, "artifact directory is required")
		os.Exit(2)
	}

	prover, err := openProver(*artifacts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prover initialization failed")
		os.Exit(1)
	}
	if err := serve(os.Stdin, os.Stdout, prover); err != nil {
		fmt.Fprintln(os.Stderr, "prover protocol failed")
		os.Exit(1)
	}
}
