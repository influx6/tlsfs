package std

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"sync"

	"github.com/fatih/color"
	"github.com/gokit/history"
)

var (
	newline   = "\n"
	red       = color.New(color.FgRed)
	green     = color.New(color.FgHiGreen)
	bggreen   = color.New(color.BgGreen)
	blue      = color.New(color.BgHiBlue)
	white     = color.New(color.FgWhite)
	yellow    = color.New(color.FgHiYellow)
	magenta   = color.New(color.FgHiMagenta)
	bgmagenta = color.New(color.BgHiMagenta)
	pb        = sync.Pool{New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 1024))
	}}
)

var (
	// Std exposes a package level formatter which prints all instances of history.B
	// to the os.Stderr file.
	Std = FlatPrint(os.Stderr)
)

// FlatPrintf returns a history.Handler which uses the flatPrinter with provided writer.
func FlatPrint(w io.Writer) history.Handler {
	return StdFunc(flatPrinter{}, w)
}

// StdFunc returns a history.Handler which uses the printer to craft the
// format for a history.B instance.
func StdFunc(printer Printer, w io.Writer) history.Handler {
	return history.HandlerFunc(func(b history.BugLog) error {
		bu := pb.Get().(*bytes.Buffer)
		bu.Reset()
		err := printer.Fprint(bu, b)
		io.Copy(w, bu)
		pb.Put(bu)
		return err
	})
}

// Printer defines an interface that exposes specific methods
// that provide custom methods to format giving parameters into
// bytes.
type Printer interface {
	Fprint(io.Writer, history.BugLog) error
}

type flatPrinter struct{}

func (fp flatPrinter) Fprint(w io.Writer, b history.BugLog) error {
	fmt.Fprintf(w, "⡿ %+s\t\t%s :%+q\n", bgmagenta.Sprint(b.Title), magenta.Sprint("Tags"), b.Tags)

	w.Write([]byte(newline))

	for _, fl := range b.Fields {
		dl, err := fp.kv(fl)
		if err != nil {
			return err
		}

		if _, err = w.Write(dl); err != nil {
			return err
		}
	}

	w.Write([]byte(newline))

	dl, err := fp.status(b.Status)
	if err != nil {
		return err
	}

	if _, err = w.Write(dl); err != nil {
		return err
	}

	w.Write([]byte(newline))

	for _, sl := range b.Metrics {
		dl, err := fp.metrics(sl)
		if err != nil {
			return err
		}

		if _, err = w.Write(dl); err != nil {
			return err
		}

		w.Write([]byte(newline))
	}

	return nil
}

func (fp flatPrinter) status(fl history.Status) ([]byte, error) {
	var kvString, inString, byString string
	if fl.Err != nil {
		kvString = fmt.Sprintf(" ⠙ %s: %+s\tErr: %+q\n", blue.Sprint("Message"), fp.level(fl.Message, fl.Level), fl.Err)
	} else {
		kvString = fmt.Sprintf(" ⠙ %s: %+s\n", blue.Sprint("Message"), fp.level(fl.Message, fl.Level))
	}

	byString = fmt.Sprintf("   %s: %+s:%d\t%+s\t\n", white.Sprint("fnCallAt"), path.Base(fl.Graph.By.Function), fl.Graph.By.Line, fl.Graph.By.File)
	inString = fmt.Sprintf("   %s: %+s:%d\t%+s\t\n", white.Sprint("fnCallIn"), path.Base(fl.Graph.In.Function), fl.Graph.In.Line, fl.Graph.In.File)
	return []byte(kvString + byString + inString), nil
}

func (flatPrinter) metrics(fl history.Metric) ([]byte, error) {
	kvString := fmt.Sprintf("\t⠙ %s  %+q\tValue: %#v\t\tMeta: %#v\n", bggreen.Sprint("METRICS"), fl.Title, fl.Value, fl.Meta)
	return []byte(kvString), nil
}

func (flatPrinter) kv(fl history.Field) ([]byte, error) {
	var value string

	if so, ok := fl.Value.(_s); ok {
		value = so.String()
	} else {
		value = fmt.Sprintf("%#v", fl.Value)
	}

	kvString := fmt.Sprintf("\t⠙ %s  %+q\t%+s\n", bggreen.Sprint("Params"), fl.Key, value)
	return []byte(kvString), nil
}

func (flatPrinter) level(ts string, ls history.Level) []byte {
	switch ls {
	case history.RedLvl:
		return []byte(red.Sprint(ts))
	case history.InfoLvl:
		return []byte(green.Sprint(ts))
	case history.ErrorLvl:
		return []byte(magenta.Sprint(ts))
	case history.YellowLvl:
		return []byte(yellow.Sprint(ts))
	}
	return nil
}

type _s interface {
	String() string
}
