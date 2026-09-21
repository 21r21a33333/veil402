package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	worker "github.com/veil402/veil402/prover/veil402-gnark/internal/protocol"
	"google.golang.org/protobuf/proto"
)

const (
	protocolVersion  = 1
	maxRequestBytes  = 2 << 20
	maxResponseBytes = 64 << 10
)

func serve(input io.Reader, output io.Writer, prover *prover, parentGone func()) error {
	if err := writeMessage(output, &worker.Ready{
		Protocol: protocolVersion,
		Artifact: prover.artifact,
	}); err != nil {
		return err
	}

	requests := make(chan *worker.Request)
	failed := make(chan error, 1)
	go readRequests(input, requests, failed, parentGone)

	next := uint64(1)
	for {
		select {
		case err := <-failed:
			return err
		case request := <-requests:
			if request.Id != next {
				clear(request.Witness)
				return errors.New("unexpected request ID")
			}
			next++
			if next == 0 {
				clear(request.Witness)
				return errors.New("request ID exhausted")
			}
			response := prove(request, prover)
			if err := writeMessage(output, response); err != nil {
				return err
			}
		}
	}
}

func readRequests(
	input io.Reader,
	requests chan<- *worker.Request,
	failed chan<- error,
	parentGone func(),
) {
	for {
		request := new(worker.Request)
		if err := readMessage(input, request); err != nil {
			if errors.Is(err, io.EOF) {
				parentGone()
			}
			failed <- err
			return
		}
		requests <- request
	}
}

func prove(request *worker.Request, prover *prover) *worker.Response {
	proof, public, err := prover.prove(request.Witness)
	clear(request.Witness)
	if err != nil {
		return &worker.Response{
			Id:      request.Id,
			Failure: worker.Failure_FAILURE_PROVE_FAILED,
		}
	}
	return &worker.Response{
		Id:     request.Id,
		Proof:  proof,
		Public: public,
	}
}

func readMessage(input io.Reader, message proto.Message) error {
	var header [4]byte
	if _, err := io.ReadFull(input, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > maxRequestBytes {
		return errors.New("request exceeded its size limit")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(input, body); err != nil {
		clear(body)
		return err
	}
	err := proto.Unmarshal(body, message)
	clear(body)
	return err
}

func writeMessage(output io.Writer, message proto.Message) error {
	body, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	if len(body) > maxResponseBytes {
		return errors.New("response exceeded its size limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if _, err := io.Copy(output, bytes.NewReader(header[:])); err != nil {
		return err
	}
	_, err = io.Copy(output, bytes.NewReader(body))
	return err
}
