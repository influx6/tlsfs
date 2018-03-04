package sysfs

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/wirekit/tlsfs"
)

// SystemZapFS implements the tlsfs.ZapFS ontop on the internal os filesystem.
type SystemZapFS struct {
	Dir string
}

// NewSystemZapFS returns a new instance of SystemZapFS which creates all
// files within the provided directory path.
func NewSystemZapFS(dir string) *SystemZapFS {
	return &SystemZapFS{
		Dir: dir,
	}
}

// Read returns the ZapFile associated with given path with their
// associated ZapTracks.
func (sm *SystemZapFS) Read(path string) (tlsfs.ZapFile, error) {
	targetPath := filepath.Join(sm.Dir, path) + ".zap"
	stat, err := os.Stat(targetPath)
	if err != nil {
		return tlsfs.ZapFile{}, err
	}

	if stat.IsDir() {
		return tlsfs.ZapFile{}, errors.New("is a directory, expected a file")
	}

	zapFile, err := os.Open(targetPath)
	if err != nil {
		return tlsfs.ZapFile{}, err
	}

	defer zapFile.Close()

	var zapper tlsfs.ZapFile
	if err := zapper.UnmarshalReader(zapFile); err != nil {
		return tlsfs.ZapFile{}, err
	}

	return zapper, nil
}

// Write returns a ZapWriter which flushes all data added to it as a single
// compressed zap file. All sections provded for the file will be gzipped.
func (sm *SystemZapFS) Write(path string) (tlsfs.ZapWriter, error) {
	return &systemWriter{
		fs:   sm,
		name: path,
	}, nil
}

// syncTracks takes giving path and writes giving tlsfs.ZapTrack into a giving file
// on the filesystem, appending .zap to it's end.
func (sm *SystemZapFS) syncTracks(path string, tracks []tlsfs.ZapTrack) error {
	targetPath := filepath.Join(sm.Dir, path) + ".zap"
	zapper := tlsfs.ZapFile{Name: path, Tracks: tracks}

	zapperFile, err := os.Create(targetPath)
	if err != nil {
		return err
	}

	defer zapperFile.Close()

	_, err = zapper.WriteGzippedTo(zapperFile)
	if err != nil {
		return err
	}

	return zapperFile.Sync()
}

type systemWriter struct {
	name   string
	fs     *SystemZapFS
	tl     sync.Mutex
	tracks []tlsfs.ZapTrack
}

func (s *systemWriter) Flush() error {
	s.tl.Lock()
	defer s.tl.Unlock()
	err := s.fs.syncTracks(s.name, s.tracks)
	return err
}

func (s *systemWriter) Add(name string, d []byte) error {
	s.tl.Lock()
	s.tracks = append(s.tracks, tlsfs.ZapTrack{Name: name, Data: d})
	s.tl.Unlock()
	return nil
}
