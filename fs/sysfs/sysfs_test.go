package sysfs_test

import (
	"bytes"
	"testing"

	"github.com/influx6/faux/tests"
	"github.com/wirekit/tlsfs/fs/sysfs"
)

func TestSystemFS_WriteRead(t *testing.T) {
	specs := []struct {
		data []byte
		name string
	}{
		{
			name: "35343434343.zap",
			data: []byte("wait!"),
		},
		{
			name: "wizzle",
			data: []byte("rock!"),
		},
		{
			name: "trunk/rack.zap",
			data: []byte("bettle!"),
		},
		{
			name: "waiting/run/rack.zap",
			data: []byte("shrug!"),
		},
	}

	fs := sysfs.NewSystemZapFS("./temp")
	for _, item := range specs {
		writer, err := fs.Write(item.name)
		if err != nil {
			tests.FailedWithError(err, "Should have received new writer from filesystem")
		}

		if err := writer.Add("disc", item.data); err != nil {
			tests.FailedWithError(err, "Should have written data into writer")
		}

		if err := writer.Flush(); err != nil {
			tests.FailedWithError(err, "Should have flushed data to writer")
		}

		reader, err := fs.Read(item.name)
		if err != nil {
			tests.FailedWithError(err, "Should have read tests data from filesystem")
		}

		disc, err := reader.Find("disc")
		if err != nil {
			tests.FailedWithError(err, "Should have retrieved 'disc' data from zap file")
		}

		if !bytes.Equal(disc.Data, item.data) {
			tests.Failed("Should have matching test data with retrieved data")
		}
		tests.Passed("Should have matching successfully written and read test %q", item.name)
	}

	items, err := fs.ReadAll()
	if err != nil {
		tests.FailedWithError(err, "Should have received response from fs")
	}
	tests.Passed("Should have received response from fs")

	if len(items) != 4 {
		tests.Info("Received: %d", len(items))
		tests.Info("Expected: %d", 4)
		tests.Failed("Should have retrieved for files")
	}
	tests.Passed("Should have retrieved for files")

	if err := fs.RemoveAll(); err != nil {
		tests.FailedWithError(err, "Should have removed all stored data")
	}
	tests.Passed("Should have removed all stored data")
}

func TestSystemFS_WriteRemove(t *testing.T) {
	fs := sysfs.NewSystemZapFS("./temp")
	writer, err := fs.Write("bob/rack.zap")
	if err != nil {
		tests.FailedWithError(err, "Should have acquired writer from fs")
	}
	tests.Passed("Should have acquired writer from fs")

	writer.Add("disc", []byte("run"))
	writer.Flush()

	if _, err = fs.Read("bob/rack.zap"); err != nil {
		tests.FailedWithError(err, "Should have retrieved saved file from fs")
	}
	tests.Passed("Should have retrieved saved file from fs")

	if err = fs.Remove("bob/rack.zap"); err != nil {
		tests.FailedWithError(err, "Should have delete file from fs")
	}
	tests.Passed("Should have delete file from fs")

	if _, err = fs.Read("bob/rack.zap"); err == nil {
		tests.FailedWithError(err, "Should have failed to retrieve saved file from fs")
	}
	tests.Passed("Should have failed to retrieve saved file from fs")
}

func TestSystemFS_WriteRemoveAll(t *testing.T) {
	fs := sysfs.NewSystemZapFS("./temp")
	writer, err := fs.Write("bob/rack.zap")
	if err != nil {
		tests.FailedWithError(err, "Should have acquired writer from fs")
	}
	tests.Passed("Should have acquired writer from fs")

	writer.Add("disc", []byte("run"))
	writer.Flush()

	if _, err = fs.Read("bob/rack.zap"); err != nil {
		tests.FailedWithError(err, "Should have retrieved saved file from fs")
	}
	tests.Passed("Should have retrieved saved file from fs")

	if err = fs.RemoveAll(); err != nil {
		tests.FailedWithError(err, "Should have delete file from fs")
	}
	tests.Passed("Should have delete file from fs")

	items, err := fs.ReadAll()
	if err != nil {
		tests.FailedWithError(err, "Should have received response from fs")
	}
	tests.Passed("Should have received response from fs")

	if len(items) != 0 {
		tests.Failed("Should have received empty slice")
	}
	tests.Passed("Should have received empty slice")
}
