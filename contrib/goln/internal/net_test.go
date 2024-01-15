package internal

import (
	"io/ioutil"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadWriterConn(t *testing.T) {
	tmp := t.TempDir()
	tmpIn, err := ioutil.TempFile(tmp, "in")
	if err != nil {
		t.Fatal(err)
	}
	defer tmpIn.Close()

	tmpOut, err := ioutil.TempFile(tmp, "out")
	if err != nil {
		t.Fatal(err)
	}
	defer tmpOut.Close()

	if _, err := tmpIn.Write([]byte("foo bar")); err != nil {
		t.Fatal(err)
	}

	if _, err := tmpIn.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	lis := NewReadWriteListener(tmpIn, tmpOut)
	conn, err := lis.Accept()
	if err != nil {
		t.Fatal(err)
	}

	var buf = make([]byte, 32)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			_, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err = conn.Write(buf); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	if _, err := tmpOut.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var buf1 = make([]byte, 32)
	_, err = tmpOut.Read(buf1)
	if err != nil {
		t.Fatal(err)
	}
	assert.EqualValues(t, buf, buf1)
}
