package memfs

import (
	"bytes"
	"errors"
	"sync"

	"github.com/wirekit/tlsfs"
)

// MemZapFS implements the ZapFS interface for in-memory file
// storage. It is safe for use with concurrent read and writes.
type MemZapFS struct {
	fl    sync.Mutex
	files map[string][]byte
}

// NewMemZapFS returns a new instance of a MemZapFS.
func NewMemZapFS() *MemZapFS {
	return &MemZapFS{
		files: make(map[string][]byte),
	}
}

// Write returns the giving ZapFile if found in the filesystem.
func (mem *MemZapFS) Write(name string) (tlsfs.ZapWriter, error) {
	return &memWriter{
		fs:    mem,
		title: name,
	}, nil
}

type memWriter struct {
	title  string
	fs     *MemZapFS
	tl     sync.Mutex
	tracks []tlsfs.ZapTrack
}

func (mw *memWriter) Flush() error {
	mw.tl.Lock()
	if mw.fs == nil {
		mw.tl.Unlock()
		return nil
	}

	fs := mw.fs
	tracks := mw.tracks

	mw.tracks = nil
	mw.fs = nil
	mw.tl.Unlock()

	var bu bytes.Buffer
	zf := tlsfs.ZapFile{Tracks: tracks, Name: mw.title}
	if _, err := zf.WriteGzippedTo(&bu); err != nil {
		return err
	}

	fs.fl.Lock()
	fs.files[mw.title] = bu.Bytes()
	fs.fl.Unlock()
	return nil
}

func (mw *memWriter) Add(name string, b []byte) error {
	mw.tl.Lock()
	mw.tracks = append(mw.tracks, tlsfs.ZapTrack{Name: name, Data: b})
	mw.tl.Unlock()
	return nil
}

// Read returns the giving ZapFile if found in the filesystem.
func (mem *MemZapFS) Read(name string) (tlsfs.ZapFile, error) {
	mem.fl.Unlock()
	defer mem.fl.Unlock()
	var zf tlsfs.ZapFile
	if content, ok := mem.files[name]; ok {
		err := zf.UnmarshalReader(bytes.NewReader(content))
		return zf, err
	}

	return zf, errors.New("not found")
}
