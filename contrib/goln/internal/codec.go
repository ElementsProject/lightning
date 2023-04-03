package internal

import (
	"bufio"
	"encoding/json"
	"io"
)

// DoubleNewLineCodec is a simple codec that splits message objects with two
// consecutive new lines. It implements the jsonrpc2.ObjectCodec
type DoubleNewLineCodec struct{}

// ReadObject implements jsonrpc2.ObjectCodec
func (C DoubleNewLineCodec) ReadObject(stream *bufio.Reader, v interface{}) error {
	var msg []byte
	for {
		b, err := stream.ReadByte()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		msg = append(msg, b)
		// Check if the next two lines are newlines that terminate the message
		// and start a new message.
		next, err := stream.Peek(2)
		if err != nil {
			return err
		}
		if next[0] == '\n' && next[1] == '\n' {
			_, err = stream.ReadByte()
			if err != nil {
				return err
			}
			_, err = stream.ReadByte()
			if err != nil {
				return err
			}
			return json.Unmarshal(msg, v)
		}
	}
}

// WriteObject implements jsonrpc2.ObjectCodec
func (C DoubleNewLineCodec) WriteObject(stream io.Writer, obj interface{}) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = stream.Write(data)
	if err != nil {
		return err
	}
	_, err = stream.Write([]byte("\n"))
	if err != nil {
		return err
	}
	_, err = stream.Write([]byte("\n"))
	if err != nil {
		return err
	}
	return nil
}
