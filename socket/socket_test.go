package socket

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/digitalocean/go-libvirt/internal/constants"
)

var testHeader = []byte{
	0x20, 0x00, 0x80, 0x86, // program
	0x00, 0x00, 0x00, 0x01, // version
	0x00, 0x00, 0x00, 0x01, // procedure
	0x00, 0x00, 0x00, 0x00, // type
	0x00, 0x00, 0x00, 0x00, // serial
	0x00, 0x00, 0x00, 0x00, // status
}

func TestPktLen(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0xa} // uint32:10
	r := bytes.NewBuffer(data)

	expected := uint32(10)
	actual, err := pktlen(r)
	if err != nil {
		t.Error(err)
	}

	if expected != actual {
		t.Errorf("expected packet length %q, got %q", expected, actual)
	}
}

func TestExtractHeader(t *testing.T) {
	r := bytes.NewBuffer(testHeader)
	h, err := extractHeader(r)
	if err != nil {
		t.Error(err)
	}

	if h.Program != constants.Program {
		t.Errorf("expected Program %q, got %q", constants.Program, h.Program)
	}

	if h.Version != constants.ProtocolVersion {
		t.Errorf("expected version %q, got %q", constants.ProtocolVersion, h.Version)
	}

	if h.Procedure != constants.ProcConnectOpen {
		t.Errorf("expected procedure %q, got %q", constants.ProcConnectOpen, h.Procedure)
	}

	if h.Type != Call {
		t.Errorf("expected type %q, got %q", Call, h.Type)
	}

	if h.Status != StatusOK {
		t.Errorf("expected status %q, got %q", StatusOK, h.Status)
	}
}

// testSocket returns a Socket writing to the client end of a net.Pipe, plus
// the server end for scripting assertions. It bypasses Connect() to avoid the
// listener goroutine — SendStream exercises the write path only.
func testSocket(t *testing.T) (*Socket, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// disconnected must be an open channel: a closed one marks the socket
	// disconnected and SendPacket refuses to write.
	return &Socket{
		conn:         client,
		writer:       bufio.NewWriter(client),
		mu:           &sync.Mutex{},
		disconnected: make(chan struct{}),
	}, server
}

// readPacket reads one rpc packet (Length + Header + Payload) from conn,
// reusing the production pktlen/extractHeader parsers so their decoding is
// exercised against a real wire as a side effect of every SendStream test.
func readPacket(t *testing.T, conn net.Conn) (Header, []byte) {
	t.Helper()
	length, err := pktlen(conn)
	if err != nil {
		t.Fatalf("failed reading packet length: %v", err)
	}
	hdr, err := extractHeader(conn)
	if err != nil {
		t.Fatalf("failed reading packet header: %v", err)
	}
	// payload: packet length minus what was previously read
	payload := make([]byte, int(length)-int(unsafe.Sizeof(_p)))
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("failed reading packet payload: %v", err)
	}
	return *hdr, payload
}

// TestSendStreamAbortsViaChannel verifies the SendStream compatibility layer:
// closing the abort channel (the pre-context API) must cancel the stream
// through the context adaptation, so a StatusError packet is sent and
// SendStream returns the send result (nil) rather than a stream error.
//
// The abort is only observed between reads from the stream, so unblocking
// chunks must keep flowing after the abort until the cancellation kicks in.
func TestSendStreamAbortsViaChannel(t *testing.T) {
	s, server := testSocket(t)

	// an io.Pipe keeps the stream open so the sender stays blocked in Read
	// between chunks
	streamR, streamW := io.Pipe()
	t.Cleanup(func() { streamW.Close() })

	abort := make(chan bool)
	done := make(chan error, 1)
	go func() {
		done <- s.SendStream(1, 2, 3, streamR, abort)
	}()

	chunk := []byte("hello libvirt")

	// the first chunk must go out as a StatusContinue data packet
	if _, err := streamW.Write(chunk); err != nil {
		t.Fatal(err)
	}
	h, payload := readPacket(t, server)
	if h.Type != Stream {
		t.Errorf("expected type %q, got %q", Stream, h.Type)
	}
	if h.Status != StatusContinue {
		t.Errorf("expected status %q, got %q", StatusContinue, h.Status)
	}
	if !bytes.Equal(payload, chunk) {
		t.Errorf("expected payload %q, got %q", chunk, payload)
	}

	// abort while SendStream is blocked reading from the stream
	close(abort)

	// there is no happens-before between the wrapper goroutine observing the
	// closed channel and the sender's next cancellation check, so keep
	// handing out chunks: each read is followed by another check, one of
	// which must see the pending cancellation
	go func() {
		for range 10 {
			if _, err := streamW.Write(chunk); err != nil {
				return
			}
		}
	}()

	// stray StatusContinue packets may precede the abort packet
	for {
		h, payload = readPacket(t, server)
		if h.Type != Stream {
			t.Fatalf("expected type %q, got %q", Stream, h.Type)
		}
		if h.Status == StatusError {
			break
		}
		if h.Status != StatusContinue {
			t.Fatalf("expected status %q, got %q", StatusContinue, h.Status)
		}
		if len(payload) == 0 {
			t.Fatal("expected non-empty data packet")
		}
	}

	// an aborted stream is not an error: SendStream reports the send result
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendStream did not return after abort")
	}
}

// TestSendStreamCompletesOnEOF verifies the happy path: the payload goes out
// as StatusContinue data packets and the stream finishes with StatusOK once
// the reader reaches EOF, without any abort.
func TestSendStreamCompletesOnEOF(t *testing.T) {
	s, server := testSocket(t)

	data := []byte("hello libvirt")
	done := make(chan error, 1)
	go func() {
		done <- s.SendStream(1, 2, 3, bytes.NewReader(data), make(chan bool))
	}()

	// data packet
	h, payload := readPacket(t, server)
	if h.Type != Stream {
		t.Errorf("expected type %q, got %q", Stream, h.Type)
	}
	if h.Status != StatusContinue {
		t.Errorf("expected status %q, got %q", StatusContinue, h.Status)
	}
	if !bytes.Equal(payload, data) {
		t.Errorf("expected payload %q, got %q", data, payload)
	}

	// stream end packet
	h, payload = readPacket(t, server)
	if h.Type != Stream {
		t.Errorf("expected type %q, got %q", Stream, h.Type)
	}
	if h.Status != StatusOK {
		t.Errorf("expected status %q, got %q", StatusOK, h.Status)
	}
	if len(payload) != 0 {
		t.Errorf("expected empty payload, got %q", payload)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendStream did not return after EOF")
	}
}
