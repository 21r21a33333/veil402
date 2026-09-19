package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
)

const maxMessageBytes = 2 << 20

type request struct {
	ID      string `json:"id"`
	Witness string `json:"witness"`
}

type response struct {
	ID      string `json:"id"`
	Proof   string `json:"proof,omitempty"`
	Public  string `json:"public,omitempty"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

func serve(input io.Reader, output io.Writer, prover *prover) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), maxMessageBytes)
	encoder := json.NewEncoder(output)

	for scanner.Scan() {
		var request request
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			if err := encoder.Encode(response{Error: "bad_request", Message: "request is malformed"}); err != nil {
				return err
			}
			continue
		}
		witness, err := base64.StdEncoding.DecodeString(request.Witness)
		if err != nil {
			if err := encoder.Encode(response{ID: request.ID, Error: "bad_witness", Message: "witness is malformed"}); err != nil {
				return err
			}
			continue
		}
		proof, public, err := prover.prove(witness)
		clear(witness)
		if err != nil {
			if err := encoder.Encode(response{ID: request.ID, Error: "prove_failed", Message: "proof generation failed"}); err != nil {
				return err
			}
			continue
		}
		if err := encoder.Encode(response{
			ID:     request.ID,
			Proof:  base64.StdEncoding.EncodeToString(proof),
			Public: base64.StdEncoding.EncodeToString(public),
		}); err != nil {
			return err
		}
	}
	return scanner.Err()
}
