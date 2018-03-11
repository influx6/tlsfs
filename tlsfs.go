package tlsfs

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"encoding/binary"

	"compress/gzip"

	"crypto"

	"crypto/x509"

	"github.com/influx6/faux/pools/pbytes"
	"github.com/wirekit/llio"
)

var (
	bits = pbytes.NewBytesPool(128, 30)

	// ErrMismatchedDecompressSize is return when giving size of decompressed is
	// not the size expected of ZapTrack.
	ErrMismatchedDecompressSize = errors.New("tlsfs.ZapTrack decompress data mismatched with expected size")

	// ErrInvalidZapTrackBytes is returned when byte slices differes from zaptrack layout.
	ErrInvalidZapTrackBytes = errors.New("[]byte content is not a valid ZapTrack data")

	// ErrInvalidRead is returned when expected read size is not met by readers .Read() call.
	ErrInvalidRead = errors.New("read failed to match expected header size")

	// ErrNotFound is returned when a giving key has no related value.
	ErrNotFound = errors.New("not found")

	// ErrExpired is returned when certificate has expired.
	ErrExpired = errors.New("not found")

	// ErrUserDisagreesWithToS is returned when user disagrees with CA Terms of Service(TOS).
	ErrUserDisagreesWithToS = errors.New("user disagrees with CA TOS")

	// ErrInvalidDomain is returned when the domain desired is invalid
	ErrInvalidDomain = errors.New("domain value is invalid")

	// ErrCertificateHasNoBundle is returned when the domain desired is invalid
	ErrErrCertificateHasNoBundle = errors.New("domain certificate has no bundled data")

	// ErrZapFileDomainMismatched is returned when given domain does not match data in file.
	ErrZapFileDomainMismatched = errors.New("ZapFile domain-account.Domain does not match expected")

	// ErrZapFileHasNoAcctData is returned when a zapfile contains no acct data for a domain.
	ErrZapFileHasNoAcctData = WithZapCorrupted(errors.New("ZapFile contains no domain-account data"))

	// ErrZapFileHasNoPKeyData is returned when a zapfile contains no private key data for a domain.
	ErrZapFileHasNoPKeyData = WithZapCorrupted(errors.New("ZapFile contains no domain-private-key data"))

	// ErrZapFileHasNoUserRegistrationData is returned when a zapfile contains no user registration data for a domain.
	ErrZapFileHasNoUserRegistrationData = WithZapCorrupted(errors.New("ZapFile contains no domain-user-registration-data data"))

	// ErrZapFileHasNoCertificate is returned when a zapfile contains no domain certificate for a domain.
	ErrZapFileHasNoCertificate = WithZapCorrupted(errors.New("ZapFile contains no domain-certificate data"))

	// ErrZapFileHasNoIssuerCertificate is returned when a zapfile contains no domain issuer certificate
	// from the CA for a domain.
	ErrZapFileHasNoIssuerCertificate = WithZapCorrupted(errors.New("ZapFile contains no domain-issuer-certificate data"))

	// ErrZapFileHasNoCertificateRequest is returned when a zapfile contains no domain certificate
	// request or CRS, that was used to generate the domain certificate for a domain.
	ErrZapFileHasNoCertificateRequest = WithZapCorrupted(errors.New("ZapFile contains no domain-certificate-request data"))
)

// constants of certificate life-times.
const (
	// Live40Weeks sets the duration representing the number of hours in a 40 days period.
	Live40Days = time.Hour * 960

	// Live30Weeks sets the duration representing the number of hours in a 30 days period.
	Live30Days = time.Hour * 720

	// Live2Weeks sets the duration representing the number of hours in all the days in a 2 week period.
	Live2Weeks = time.Hour * 366

	// OneYear sets the duration representing the number of hours in all the days in a year.
	OneYear = time.Hour * 8766

	// ThreeMonths sets the duration of representing the number of hours in a 3 months period.
	ThreeMonths = time.Hour * 2190
)

const (
	// DomainNameDataZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	DomainNameDataZapName = "domain-uri-name"

	// DomainUserDataZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	DomainUserDataZapName = "domain-user-email"

	// DomainBundleDataZapName sets the name used to store the zap track for the domain
	// certificate bundle zap file
	DomainBundleDataZapName = "domain-bundle-data"

	// DomainPrivateKeyZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	DomainPrivateKeyZapName = "domain-private-key"

	// DomainCertificateZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	DomainCertificateZapName = "domain-certificate"

	// DomainUserRegistrationDataZapName sets the name used to store the zap track for the domain
	// user registration data in a zap file.
	DomainUserRegistrationDataZapName = "domain-user-registration-data"

	// IssuerDomainCertificateZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	IssuerDomainCertificateZapName = "domain-issuer-certificate"

	// DomainCertificateRequestZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	DomainCertificateRequestZapName = "domain-certificate-request"
)

//*************************************************************
// NotExists interface
//*************************************************************

// NotExists is define to provide a clear distinct means of identify
// a given error has one that relates to the non-existence of a desired
// find. It provides a more robust approach to dealing with
// existence/non-existence errors instead of evaluating the equality
// of a declared error to another.
type NotExists interface {
	error
	NotExists()
}

//*************************************************************
// ZapFS interface
//*************************************************************

// ZapWriter defines an interface which returns a
// set of methods to add a series of byte slice with
// associated names to a underline zap filesystem.
type ZapWriter interface {
	Flush() error
	Add(string, []byte) error
}

// ZapFS defines an interface that exposes a filesystem to
// power the storage/retrieval of tls certificates with ease.
type ZapFS interface {
	Remove(string) error
	ReadAll() ([]ZapFile, error)
	Read(string) (ZapFile, error)
	Write(string) (ZapWriter, error)
}

//*************************************************************
// Certificate Status Flag
//*************************************************************

const (
	// OPFailed represents the critical state of a request for the creation/renewal or removal of
	// a existing certificate either with CA or underline file system.
	OPFailed StatusFlag = iota + 1

	// CACExpired represents the state where a certificate is totally expired.
	CACExpired

	// CARenewalCriticalExpiration states the certificate to have failed renewal
	// and lies below two weeks expiration limit and requires user actions due to an
	// unexpected error.
	CARenewalCriticalExpiration

	// CARenewalEarlyExpiration states the certificate to have fallen into the
	// 30-days expiration limit and renewal had failed due to unknown CA reasons
	// that require manual user action.
	CARenewalEarlyExpiration

	// CACriticalRenewedRequired states the given certificates requires immediate renewal
	// from it's CA on a critical level where it is below or around 2 weeks to expiration.
	CACriticalRenewedRequired

	// CARenewedRequired states the given certificates requires immediate renewal
	// from it's CA.
	CARenewedRequired

	// Renewed is the state returned when a renewed operation succeeded for a
	// existing certificate.
	Renewed

	// Created is the state returned when the new certificate request succeeded.
	Created

	// Live is returned when a giving certificate is still in good shape for use.
	Live
)

// StatusFlag defines a int type indicating the status of
// a flag creation/renewal/removal state.
type StatusFlag int8

// String returns the a short phrase suitable for the giving
// status flag number.
func (s StatusFlag) String() string {
	switch s {
	case OPFailed:
		return "1 - OP FAILED"
	case CACExpired:
		return "2 - CA CERTIFICATE EXPIRED"
	case CARenewalCriticalExpiration:
		return "3 - CA CERTIFICATE RENEWAL REDALERT STATE"
	case CARenewalEarlyExpiration:
		return "4 - CA CERTIFICATE RENEWAL CRITICAL STATE"
	case CACriticalRenewedRequired:
		return "5 - CA CERTIFICATE RENEWAL REQUIRED"
	case CARenewedRequired:
		return "6 - CA CERTIFICATE RENEWAL ADVICED"
	case Renewed:
		return "7 - CA CERTIFICATE RENEWED"
	case Created:
		return "8 - CA CERTIFICATE ISSUED"
	case Live:
		return "9 - CA CERTIFICATE STILL LIVE"
	}

	return "0 - UNKNOWN STATE"
}

// Status defines a interface type that exposes a method to
// return the status flag of a giving certificate.
type Status interface {
	// Reason returns an error if such occured about the non-critical
	// failure of a creation/renewal of a certificate requests.
	Reason() error

	// Flag returns the status flag representing the status of
	// a certificate creation/renewal.
	Flag() StatusFlag
}

// WithStatus returns a StatusFlag with provided flag.
func WithStatus(flag StatusFlag, reason error) Status {
	return tlstatus{flag: flag, reason: reason}
}

type tlstatus struct {
	flag   StatusFlag
	reason error
}

// Reason implements the Status interface Reason method.
func (tl tlstatus) Reason() error {
	return tl.reason
}

// Flag implements the Status interface Flag method.
func (tl tlstatus) Flag() StatusFlag {
	return tl.flag
}

//*************************************************************
// TlsFS interface and implementation
//*************************************************************

// AgreeToTOS defines a variable which implements the TOSAction interface.
// It always returns true to agree to a TOS action request.
var AgreeToTOS TOSAction = func(_ string) bool { return true }

// TOSAction defines a function called to receive user response
// towards the need to agree to a CA Terms of service.
type TOSAction func(tosURL string) bool

// TLSFS defines an interface which exposes methods to create
// tls certificates from a given root CA and have the underline
// certificates be stored within a underline ZapFS.
type TLSFS interface {
	All() ([]DomainAccount, error)
	GetUser(email string) (Account, error)
	Revoke(email string, domain string) error
	Get(email string, domain string) (TLSDomainCertificate, Status, error)
	Renew(email string, domain string) (TLSDomainCertificate, Status, error)
	Create(account NewDomain, action TOSAction) (TLSDomainCertificate, Status, error)
}

// TLSDomainCertificate defines a giving structure which holds generated
// certificates with associated tls.Certificates received from
type TLSDomainCertificate struct {
	User              string                   `json:"acct" description:"acct email related to the domain user"`
	Domain            string                   `json:"domain" description:"domain generated certificate"`
	Certificate       *x509.Certificate        `json:"certificate" description:"certificate generate for request and account"`
	IssuerCertificate *x509.Certificate        `json:"issuer_certificate" description:"issuer/CA certificate bundled with generate certificate"`
	Request           *x509.CertificateRequest `json:"req" description:"certificate request to build certificate"`
	Bundle            interface{}              `json:"bundle" description:"certificate bundle received from issuer/CA"`
}

// KeyType defines the custom key-type acceptable for
// user private key generation.
type KeyType string

// constants of key-types
const (
	RSA2048  = KeyType("RSA-2048")
	RSA4096  = KeyType("RSA-4096")
	RSA8192  = KeyType("RSA-8192")
	ECKey256 = KeyType("EC-P256")
	ECKey384 = KeyType("EC-P384")
	ECKey512 = KeyType("EC-P512")
)

// NewDomain defines the data which is supplied for the creation
// of certificates for a given user identified by it's email.
type NewDomain struct {
	Email      string  `json:"email" description:"email for certificate user"`
	KeyType    KeyType `json:"type" description:"key type for private key"`
	Domain     string  `json:"domain" description:"domain for certificate creation"`
	CommonName string  `json:"common_name" description:"common name for certificate must not be empty else put '*'"`

	// Optional fields providing extra meta-data, most CA especially like
	// LetsEncrypt, who will not use these, as it will retrieve from Domain
	// through AAA dns record.
	Version  int      `json:"version" description:"version to be used for generated certificate"`
	Country  string   `json:"country" description:"country of owner of certificate"`
	Province string   `json:"province" description:"province of owner of certificate"`
	Local    string   `json:"local" description:"locality of owner of certificate"`
	Address  string   `json:"address" description:"address of owner of certificate"`
	Postal   string   `json:"postal" description:"postal address for certificate"`
	DNSNames []string `json:"dns_names" description:"SNI-compliant names to be added to certificate request"`
}

// Account defines a type which represents a given registered
// user from a acme.
type Account interface {
	GetEmail() string
	GetPrivateKey() crypto.PrivateKey
}

// DomainAccount defines a struct which relates a set of registered
// domain certificates to an existing user account.
type DomainAccount struct {
	Acct    Account
	Domains []TLSDomainCertificate
}

// DomainAccounts defines a slice type of DomainAccount objects and
// implements the sort.Sort interface.
type DomainAccounts []DomainAccount

func (acd DomainAccounts) Len() int           { return len(acd) }
func (acd DomainAccounts) Swap(i, j int)      { acd[i], acd[j] = acd[j], acd[i] }
func (acd DomainAccounts) Less(i, j int) bool { return acd[i].Acct.GetEmail() < acd[j].Acct.GetEmail() }

//*************************************************************
// ZapFS: Tracks and Files
//*************************************************************

// ZapFile defines a internal file format that stores all
// internal tracks as a single, gzipped compressed file format.
type ZapFile struct {
	Name   string
	Tracks []ZapTrack
	maps   map[string]int
}

// Find attempts to find giving ZapTrack with associated name.
func (zt *ZapFile) Find(name string) (ZapTrack, error) {
	if zt.maps == nil {
		zt.maps = make(map[string]int)
	}
	if index, has := zt.maps[name]; has {
		return zt.Tracks[index], nil
	}

	// if we have disparity with cache and tracks, rebuild cache.
	if len(zt.maps) != len(zt.Tracks) {
		zt.buildCache()
	}

	if index, has := zt.maps[name]; has {
		return zt.Tracks[index], nil
	}

	return ZapTrack{}, ErrNotFound
}

// buildCache populates the internal
func (zt *ZapFile) buildCache() {
	zt.maps = make(map[string]int)
	for index, track := range zt.Tracks {
		zt.maps[track.Name] = index
	}
}

// WriteFlatTo writes the data of a ZapFile without any compression
// into provided writer.
func (zt ZapFile) WriteFlatTo(w io.Writer) (int64, error) {
	return zt.format(false, w)
}

// WriteGzippedTo writes the data of a ZapFile with gzip compression
// into provided writer.
func (zt ZapFile) WriteGzippedTo(w io.Writer) (int64, error) {
	return zt.format(true, w)
}

// UnmarshalReader takes a giving reader and attempts to decode it's
// content has a ZapFile either compressed or uncompressed.
func (zt *ZapFile) UnmarshalReader(r io.Reader) error {
	zt.maps = make(map[string]int)

	br := bufio.NewReader(r)
	header := make([]byte, 9)

	hread, err := br.Read(header)
	if err != nil {
		return err
	}

	if hread != 9 {
		return errors.New("failed to read length header")
	}

	cbit := int8(header[0])
	tagLen := int(binary.BigEndian.Uint32(header[1:5]))
	contentLen := int(binary.BigEndian.Uint32(header[5:9]))

	tag := make([]byte, tagLen)
	tread, err := br.Read(tag)
	if err != nil {
		return err
	}

	if tread != tagLen {
		return errors.New("failed to read tag name data")
	}

	zt.Name = string(tag)

	var lr *llio.LengthRecvReader
	if cbit == 0 {
		lr = llio.NewLengthRecvReader(br, 4)
	} else {
		gr, err := gzip.NewReader(br)
		if err != nil {
			return err
		}

		defer gr.Close()
		lr = llio.NewLengthRecvReader(gr, 4)
	}

	var tracks []ZapTrack
	var trackData []byte

	var readin int

	for {
		header, err := lr.ReadHeader()
		if err != nil {
			if err != io.EOF {
				return err
			}

			break
		}

		// make space for data to be read, then put back header of
		// total data length.
		trackData = make([]byte, header+4)
		binary.BigEndian.PutUint32(trackData[0:4], uint32(header))

		// Read into space for track data after length area of data.
		n, err := lr.Read(trackData[4:])
		if err != nil {
			return err
		}

		if n != header {
			return ErrInvalidRead
		}

		readin += header + 4

		var track ZapTrack
		if err := track.UnmarshalBytes(trackData); err != nil {
			return err
		}

		zt.maps[track.Name] = len(tracks)
		tracks = append(tracks, track)
	}

	if contentLen != readin {
		return errors.New("invalid content length with content read")
	}

	zt.Tracks = tracks
	return nil
}

func (zt ZapFile) format(gzipped bool, w io.Writer) (int64, error) {
	tagLen := len(zt.Name)

	hzone := tagLen + 9
	header := make([]byte, hzone)

	if gzipped {
		header[0] = byte(1)
	} else {
		header[0] = byte(0)
	}

	// Write into header total size of name.
	binary.BigEndian.PutUint32(header[1:5], uint32(tagLen))

	var contentLen int
	var contents bytes.Buffer
	if gzipped {
		gzw := gzip.NewWriter(&contents)
		//gzw.Name = zt.Name
		gzw.ModTime = time.Now()

		wc := &counterWriter{w: gzw}
		for _, track := range zt.Tracks {
			if _, err := track.WriteTo(wc); err != nil {
				return 0, err
			}
		}

		if err := gzw.Flush(); err != nil {
			return 0, err
		}

		if err := gzw.Close(); err != nil {
			return 0, err
		}

		contentLen = int(atomic.LoadInt64(&wc.n))
	} else {
		for _, track := range zt.Tracks {
			if _, err := track.WriteTo(&contents); err != nil {
				return 0, err
			}
		}

		contentLen = contents.Len()
	}

	// Write into header total size of content.
	binary.BigEndian.PutUint32(header[5:9], uint32(contentLen))

	// copy into available space name of content and ensure length range.
	if copy(header[9:], []byte(zt.Name)) != tagLen {
		return 0, io.ErrShortWrite
	}

	nheader, err := w.Write(header)
	if err != nil {
		return 0, err
	}

	cheader, err := io.Copy(w, &contents)
	if err != nil {
		return 0, err
	}

	return cheader + int64(nheader), nil
}

func (zt ZapFile) trackSize() int {
	var total int
	for _, track := range zt.Tracks {
		total += len(track.Name) + len(track.Data) + 12
	}
	return total
}

// ZapTrack defines a structure which defines a giving
// data track of a continuous-single-lined file data track.
// It represent a single data entity which is represented
// as a single file by the ZapFile format.
type ZapTrack struct {
	Name string
	Data []byte
}

// UnmarshalBytes takes giving bytes validating its's
// content to match the ZapTrack layout format, then
// setting it's Fields to appropriate contents of the
// data.
func (zt *ZapTrack) UnmarshalBytes(b []byte) error {
	bLen := len(b)
	if bLen <= 12 {
		return ErrInvalidZapTrackBytes
	}

	data := b[12:]
	zapsize := binary.BigEndian.Uint32(b[0:4])
	if bLen-4 != int(zapsize) {
		return ErrInvalidZapTrackBytes
	}

	tagsize := binary.BigEndian.Uint32(b[4:8])
	if len(data) <= int(tagsize) {
		return ErrInvalidZapTrackBytes
	}

	tagName := data[0:int(tagsize)]
	data = data[int(tagsize):]

	datasize := binary.BigEndian.Uint32(b[8:12])
	if len(data) != int(datasize) {
		return ErrInvalidZapTrackBytes
	}

	zt.Name = string(tagName)
	zt.Data = data
	return nil
}

// WriteTo implements the io.WriterTo taht writes the
// contents of a ZapTrack as a uncompressed data stream
// with appropriate header information regarding the
// data.
func (zt ZapTrack) WriteTo(w io.Writer) (int64, error) {
	dmsize := make([]byte, 12)
	bitsize := len(zt.Name) + len(zt.Data) + 8
	binary.BigEndian.PutUint32(dmsize[0:4], uint32(bitsize))
	binary.BigEndian.PutUint32(dmsize[4:8], uint32(len(zt.Name)))
	binary.BigEndian.PutUint32(dmsize[8:12], uint32(len(zt.Data)))

	decompress := bits.Get(int(bitsize))
	defer bits.Put(decompress)

	if n, err := decompress.Write(dmsize); err != nil {
		return int64(n), err
	}

	if n, err := decompress.Write([]byte(zt.Name)); err != nil {
		return int64(n), err
	}

	if n, err := decompress.Write(zt.Data); err != nil {
		return int64(n), err
	}

	nx, err := decompress.WriteTo(w)
	if err != nil {
		return nx, err
	}

	if int(nx)-4 != bitsize {
		return nx, io.ErrShortWrite
	}

	return nx, nil
}

//*************************************************************
// CorruptedError
//*************************************************************

var _ error = ZapCorruptedError{}

// ZapCorruptedError defines an zap error which contain a given reason
// for the case of a corrupted zap file.
type ZapCorruptedError struct {
	Reason error
	File   string
}

// WithZapCorrupted error returns a new instance of ZapCorruptedError.
func WithZapCorrupted(err error) *ZapCorruptedError {
	return &ZapCorruptedError{Reason: err}
}

// Error implements the error interface.
func (zc ZapCorruptedError) Error() string {
	msg := "ZapFile Corrupted: " + zc.Reason.Error()
	if zc.File != "" {
		msg += " File: " + zc.File
	}
	return msg
}

//*************************************************************
//  internal types and methods
//*************************************************************

type counterWriter struct {
	n int64
	w io.Writer
}

func (c *counterWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	atomic.AddInt64(&c.n, int64(n))
	return n, err
}
