package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	eccbn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/reilabs/sunspot/go/acir"
	sunbn254 "github.com/reilabs/sunspot/go/bn254"
)

//go:embed artifacts/transaction-v2/manifest.json
var pinnedManifest []byte

type manifest struct {
	ID      string `json:"id"`
	Noir    string `json:"noir"`
	Circuit string `json:"circuit"`
	Files   struct {
		ACIR string `json:"acir"`
		CCS  string `json:"ccs"`
		PK   string `json:"pk"`
		VK   string `json:"vk"`
	} `json:"files"`
}

type prover struct {
	artifact string
	program  acir.ACIR[*sunbn254.BN254Field, constraint.U64]
	ccs      constraint.ConstraintSystem
	pk       groth16.ProvingKey
	vk       groth16.VerifyingKey
}

func openProver(directory string) (*prover, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(manifestBytes, pinnedManifest) {
		return nil, errors.New("manifest does not match this worker")
	}
	var manifest manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, err
	}
	paths := map[string]string{
		"transaction.json": manifest.Files.ACIR,
		"transaction.ccs":  manifest.Files.CCS,
		"transaction.pk":   manifest.Files.PK,
		"transaction.vk":   manifest.Files.VK,
	}
	for name, expected := range paths {
		if err := verifyFile(filepath.Join(directory, name), expected); err != nil {
			return nil, err
		}
	}

	program, err := acir.LoadACIR[*sunbn254.BN254Field, constraint.U64](filepath.Join(directory, "transaction.json"))
	if err != nil {
		return nil, err
	}
	if program.NoirVersion != manifest.Noir || fmt.Sprint(program.Hash) != manifest.Circuit {
		return nil, errors.New("artifact identity mismatch")
	}

	ccs := groth16.NewCS(ecc.BN254)
	if err := read(filepath.Join(directory, "transaction.ccs"), ccs); err != nil {
		return nil, err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := read(filepath.Join(directory, "transaction.pk"), pk); err != nil {
		return nil, err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := read(filepath.Join(directory, "transaction.vk"), vk); err != nil {
		return nil, err
	}

	return &prover{artifact: manifest.ID, program: program, ccs: ccs, pk: pk, vk: vk}, nil
}

func (prover *prover) prove(encoded []byte) ([]byte, []byte, error) {
	full, err := witnessFromBytes(&prover.program, encoded, eccbn254.ID.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	proof, err := groth16.Prove(prover.ccs, prover.pk, full)
	if err != nil {
		return nil, nil, err
	}
	public, err := full.Public()
	if err != nil {
		return nil, nil, err
	}
	if err := groth16.Verify(proof, prover.vk, public); err != nil {
		return nil, nil, err
	}

	var proofBytes bytes.Buffer
	if _, err := proof.WriteRawTo(&proofBytes); err != nil {
		return nil, nil, err
	}
	var publicBytes bytes.Buffer
	if _, err := public.WriteTo(&publicBytes); err != nil {
		return nil, nil, err
	}
	return proofBytes.Bytes(), publicBytes.Bytes(), nil
}

func witnessFromBytes(
	program *acir.ACIR[*sunbn254.BN254Field, constraint.U64],
	encoded []byte,
	field *big.Int,
) (witness.Witness, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() {
		_, writeErr := io.Copy(writer, bytes.NewReader(encoded))
		closeErr := writer.Close()
		if writeErr != nil {
			done <- writeErr
			return
		}
		done <- closeErr
	}()

	path := fmt.Sprintf("/dev/fd/%d", reader.Fd())
	result, readErr := program.GetWitness(path, field)
	closeErr := reader.Close()
	writeErr := <-done
	if readErr != nil {
		return nil, readErr
	}
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return result, nil
}

func verifyFile(path string, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("artifact checksum mismatch")
	}
	return nil
}

func read(path string, target io.ReaderFrom) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = target.ReadFrom(file)
	return err
}
