package sysfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/wirekit/tlsfs"
)

var _ tlsfs.ZapFS = &SystemZapFS{}

// ErrIsDir is returned when target file is a directory and not a file.
var ErrIsDir = errors.New("is a directory, expected a file")

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

// RemoveAll deletes the container of all stored zap files.
func (sm *SystemZapFS) RemoveAll() error {
	return os.RemoveAll(sm.Dir)
}

// Remove removes the underline path if it exists from the filesystem.
func (sm *SystemZapFS) Remove(path string) error {
	targetPath := filepath.Join(sm.Dir, path)
	if !strings.HasSuffix(targetPath, ".zap") {
		targetPath += ".zap"
	}

	stat, err := os.Stat(targetPath)
	if err != nil {
		return err
	}

	if stat.IsDir() {
		return ErrIsDir
	}

	return os.Remove(targetPath)
}

// ReadAll returns all ZapFiles within given directory of the filesystem.
func (sm *SystemZapFS) ReadAll() ([]tlsfs.ZapFile, error) {
	var zones []tlsfs.ZapFile

	err := filepath.Walk(sm.Dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".zap") {
			return nil
		}

		//rel := filepath.Rel(sm.Dir, path)

		zapFile, err := os.Open(path)
		if err != nil {
			return err
		}

		defer zapFile.Close()

		var zapper tlsfs.ZapFile
		if err := zapper.UnmarshalReader(zapFile); err != nil {
			return err
		}

		zones = append(zones, zapper)
		return nil
	})

	if os.IsNotExist(err) {
		return zones, nil
	}

	return zones, err
}

// Read returns the ZapFile associated with given path with their
// associated ZapTracks.
func (sm *SystemZapFS) Read(path string) (tlsfs.ZapFile, error) {
	targetPath := filepath.Join(sm.Dir, path)
	if !strings.HasSuffix(targetPath, ".zap") {
		targetPath += ".zap"
	}

	stat, err := os.Stat(targetPath)
	if err != nil {
		return tlsfs.ZapFile{}, notExists{err: err}
	}

	if stat.IsDir() {
		return tlsfs.ZapFile{}, ErrIsDir
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

// WriteFile writes provided ZapFile into fs.
func (sm *SystemZapFS) WriteFile(zapped tlsfs.ZapFile) error {
	return sm.syncFile(zapped)
}

// Write returns a ZapWriter which flushes all data added to it as a single
// compressed zap file. All sections provided for the file will be gzipped.
func (sm *SystemZapFS) Write(path string) (tlsfs.ZapWriter, error) {
	return &systemWriter{
		fs:   sm,
		name: path,
	}, nil
}

// syncTracks takes giving path and writes giving tlsfs.ZapTrack into a giving file
// on the filesystem, appending .zap to it's end.
func (sm *SystemZapFS) syncTracks(path string, tracks []tlsfs.ZapTrack) error {
	return sm.syncFile(tlsfs.ZapFile{Name: path, Tracks: tracks})
}

func (sm *SystemZapFS) syncFile(zapped tlsfs.ZapFile) error {
	toPath := filepath.Join(sm.Dir, zapped.Name)
	if !strings.HasSuffix(toPath, ".zap") {
		toPath += ".zap"
	}

	newDir := filepath.Dir(toPath)
	if newDir != "." {
		if _, err := os.Stat(newDir); err != nil {
			if os.IsNotExist(err) {
				if err := os.MkdirAll(newDir, 0777); err != nil {
					return err
				}
			}
		}
	}

	zapperFile, err := os.Create(toPath)
	if err != nil {
		return err
	}

	defer zapperFile.Close()

	_, err = zapped.WriteGzippedTo(zapperFile)
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

type notExists struct {
	err error
}

func (n notExists) Error() string {
	return n.err.Error()
}

func (n notExists) NotExists() {
}
