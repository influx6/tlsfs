package memfs

import (
	"bytes"
	"errors"
	"sync"

	"github.com/wirekit/tlsfs"
)

var _ tlsfs.ZapFS = &MemFS{}

// MemFS implements the ZapFS interface for in-memory file
// storage. It is safe for use with concurrent read and writes.
type MemFS struct {
	fl    sync.Mutex
	files map[string][]byte
}

// NewMemFS returns a new instance of a MemFS.
func NewMemFS() *MemFS {
	return &MemFS{
		files: make(map[string][]byte),
	}
}

// ReadAll returns all ZapFile available in memory.
func (mem *MemFS) ReadAll() ([]tlsfs.ZapFile, error) {
	mem.fl.Lock()
	defer mem.fl.Unlock()

	files := make([]tlsfs.ZapFile, 0, len(mem.files))

	for _, data := range mem.files {
		var zf tlsfs.ZapFile
		if err := zf.UnmarshalReader(bytes.NewReader(data)); err != nil {
			return nil, err
		}

		files = append(files, zf)
	}

	return files, nil
}

// Read returns the giving ZapFile if found in the filesystem.
func (mem *MemFS) Read(name string) (tlsfs.ZapFile, error) {
	mem.fl.Lock()
	defer mem.fl.Unlock()
	var zf tlsfs.ZapFile
	if content, ok := mem.files[name]; ok {
		err := zf.UnmarshalReader(bytes.NewReader(content))
		return zf, err
	}

	return zf, notExists{err: errors.New("error not found")}
}

// Remove removes the giving file from memory.
func (mem *MemFS) Remove(name string) error {
	mem.fl.Lock()
	delete(mem.files, name)
	mem.fl.Unlock()
	return nil
}

// RemoveAll deletes the container of all stored zap bytes in memory.
func (mem *MemFS) RemoveAll() error {
	mem.fl.Lock()
	mem.files = make(map[string][]byte)
	mem.fl.Unlock()
	return nil
}

// WriteFile adds the giving ZapFile into the filesystem.
func (mem *MemFS) WriteFile(zapped tlsfs.ZapFile) (error) {
	var bu bytes.Buffer
	if _, err := zapped.WriteGzippedTo(&bu); err != nil {
		return err
	}

	mem.fl.Lock()
	mem.files[zapped.Name] = bu.Bytes()
	mem.fl.Unlock()
	return nil
}

// Write returns ZapWriter to write contents as a zap file.
func (mem *MemFS) Write(name string) (tlsfs.ZapWriter, error) {
	return &memWriter{
		fs:    mem,
		title: name,
	}, nil
}

type memWriter struct {
	title  string
	fs     *MemFS
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

type notExists struct {
	err error
}

func (n notExists) Error() string {
	return n.err.Error()
}

func (n notExists) NotExists() {
}
