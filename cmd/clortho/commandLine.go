package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/x25519"
)

// PublicOut is the common set of command flags that control how the public portion
// of the generated key is written.  By default, the public key isn't written separately.
type PublicOut struct {
	PubOutput string `placeholder:"FILE" xor:"pub-output,pub-append" help:"file to output the public portion of the generated key.  '-' indicates stdout.  if neither --pub-output nor --pub-append are specified, the public key will not be written separately.  this cannot refer to the same location as the generated private key."`
	PubAppend string `placeholder:"FILE" xor:"pub-output,pub-append" help:"file to which the generated public key will be appended.  '-' indicates reading public keys from stdin, appending the generated public key, then writing out the set to stdout.  this cannot refer to the same location as the generated private key."`
	PubFormat string `placeholder:"FORMAT" help:"the output format for the public key, one of pem, jwk, or jwk-set.  if not supplied, the output format will be detected from the output file suffix or, if output is going to stdout, the format of the keys being appended to (if any).  jwk-set is used if no format can be detected."`
}

// path returns the path information describing where the public key is to be written.
// By default, the returned path will be the empty string, indicating that no separate
// public key output should occur.
func (pout PublicOut) path() (path string, isAppend bool, err error) {
	switch {
	case len(pout.PubAppend) > 0:
		isAppend = true
		path, err = filepath.Abs(pout.PubAppend)

	case pout.PubOutput == StreamPath:
		path = StreamPath

	case len(pout.PubOutput) > 0:
		path, err = filepath.Abs(pout.PubOutput)
	}

	return
}

// GeneratedOut is the common flags governing how a generated key is output.  By default, output
// is sent to stdout and the format is jwk-set.
type GeneratedOut struct {
	Output string `placeholder:"FILE" short:"o" xor:"output,append" help:"file to output the generated key.  '-' indicates stdout, which is the default."`
	Append string `placeholder:"FILE" short:"a" xor:"output,append" help:"file to append the generated key.  '-' indicates reading keys from stdin, appending the generated key, then writing the resulting set to stdout."`
	Format string `placeholder:"FORMAT" short:"f" help:"the output format for the generated private key, one of pem, jwk, or jwk-set.  if not supplied, the output format will be detected from the output file suffix or, if output is going to stdout, the format of the keys being appended to (if any).  jwk-set is used if no format can be detected."`
}

// path returns the location information controlling where the generated key is output.
// By default, the returned path will be StreamPath, indicated stdout.
func (gout GeneratedOut) path() (path string, isAppend bool, err error) {
	switch {
	case len(gout.Append) > 0:
		isAppend = true
		path, err = filepath.Abs(gout.Append)

	case gout.Output == "" || gout.Output == StreamPath:
		// by default, write the key to stdout
		path = StreamPath

	default:
		path, err = filepath.Abs(gout.Output)
	}

	return
}

// RSA holds the command line options for generating RSA keys.
type RSA struct {
	Size      uint      `short:"s" default:"256" help:"the size of the key to generate, in bits"`
	PublicOut PublicOut `embed:""`
}

func (r *RSA) AfterApply(ctx *kong.Context, random io.Reader) error {
	rawKey, err := rsa.GenerateKey(random, int(r.Size))
	if err != nil {
		return err
	}

	key, err := jwk.New(rawKey)
	if err != nil {
		return err
	}

	ctx.BindTo(key, (*jwk.Key)(nil))
	ctx.Bind(&r.PublicOut)
	return nil
}

// EC holds the command line options for generating elliptic curve keys.
type EC struct {
	Curve     string    `name:"crv" default:"P-256" enum:"P-256,P-384,P-521" help:"the elliptic curve to use"`
	PublicOut PublicOut `embed:""`
}

func (e *EC) AfterApply(ctx *kong.Context, random io.Reader) error {
	var curve elliptic.Curve
	switch e.Curve {
	// NOTE: P224 curves are explicitly not supported by the JWK standard

	case "P-256":
		curve = elliptic.P256()

	case "P-384":
		curve = elliptic.P384()

	case "P-521":
		curve = elliptic.P521()

	default:
		// this should never happen, since we have an enum constraint on the command line flag
		return fmt.Errorf("Unsupported crv: %s", e.Curve)
	}

	rawKey, err := ecdsa.GenerateKey(curve, random)
	if err != nil {
		return err
	}

	key, err := jwk.New(rawKey)
	if err != nil {
		return err
	}

	ctx.BindTo(key, (*jwk.Key)(nil))
	ctx.Bind(&e.PublicOut)
	return nil
}

// Oct holds the command line options for generating symmetric keys.
type Oct struct {
	Size uint `short:"s" default:"256" help:"the size of the key to generate, in bits"`
}

func (o *Oct) AfterApply(ctx *kong.Context, random io.Reader) error {
	byteSize := o.Size / 8
	if o.Size%8 != 0 {
		byteSize++
	}

	rawKey := make([]byte, byteSize)
	_, err := io.ReadFull(random, rawKey)
	if err != nil {
		return err
	}

	key, err := jwk.New(rawKey)
	if err != nil {
		return err
	}

	ctx.BindTo(key, (*jwk.Key)(nil))
	ctx.Bind((*PublicOut)(nil))
	return nil
}

// OKP holds the command line options for generating elliptic curve keys for signing and verifying.
type OKP struct {
	Curve     string    `name:"crv" default:"Ed25519" enum:"Ed25519,X25519" help:"the elliptic curve to use"`
	PublicOut PublicOut `embed:""`
}

func (o *OKP) AfterApply(ctx *kong.Context, random io.Reader) (err error) {
	var rawKey interface{}

	switch o.Curve {
	case "Ed25519":
		_, rawKey, err = ed25519.GenerateKey(random)

	case "X25519":
		_, rawKey, err = x25519.GenerateKey(random)

	default:
		// this should never happen, since we have an enum constraint on the command line flag
		return fmt.Errorf("Unsupported crv: %s", o.Curve)
	}

	key := jwk.NewOKPPrivateKey()
	err = key.FromRaw(rawKey)
	if err == nil {
		ctx.BindTo(key, (*jwk.Key)(nil))
	}

	ctx.Bind(&o.PublicOut)
	return
}

type CommandLine struct {
	RSA RSA `cmd:"" name:"RSA" help:"Generates RSA keys"`
	EC  EC  `cmd:"" name:"EC" help:"Generates elliptic curve keys"`
	Oct Oct `cmd:"" name:"oct" help:"Generates symmetric keys"`
	OKP OKP `cmd:"" name:"OKP" help:"generates elliptic curve edwards or montgomery keys"`

	GeneratedOut GeneratedOut `embed:""`

	KeyID      string     `name:"kid" help:"the key id"`
	KeyUsage   string     `name:"use" help:"the intended usage for the key, e.g. sig or enc"`
	KeyOps     []string   `name:"key_ops" help:"the set of key operations.  duplicate values are not allowed."`
	Algorithm  string     `name:"alg" help:"the algorithm the generated key is intended to be used with."`
	Attributes Attributes `help:"additional, nonstandard attributes.  supplying any standard JWK attributes results in an error.  values that parse as numbers as added as such.  values enclosed in single quotes are always added as strings."`

	Seed int64 `help:"the RNG seed for key generation, used primarily for testing with consistent output.  DO NOT USE FOR PRODUCTION KEYS."`
}

func (cli *CommandLine) Validate() error {
	if len(cli.KeyOps) > 0 {
		keyOps := make(map[string]bool, len(cli.KeyOps))
		for _, v := range cli.KeyOps {
			if keyOps[v] {
				return fmt.Errorf("Duplicate key op '%s'", v)
			}

			keyOps[v] = true
		}
	}

	return nil
}

func (cli *CommandLine) AfterApply(k *kong.Kong, ctx *kong.Context) error {
	if cli.Seed != 0 {
		// IMPORTANT:  This is for testing, so that repeated invocations will produce
		// the same key.  DO NOT USE FOR PRODUCTION KEYS.
		ctx.BindTo(
			mrand.New(mrand.NewSource(cli.Seed)),
			(*io.Reader)(nil),
		)
	} else {
		ctx.BindTo(
			crand.Reader,
			(*io.Reader)(nil),
		)
	}

	return nil
}

// setAttributes sets both the key attributes established by command line options, e.g. kid,
// and the extra attributes.
func (cli *CommandLine) setAttributes(generatedKey jwk.Key) error {
	if err := cli.Attributes.SetTo(generatedKey); err != nil {
		return err
	}

	// NOTE: jwk.Key.Set is documented as not returning an error
	// for the keys we're setting below

	if len(cli.KeyID) > 0 {
		generatedKey.Set(jwk.KeyIDKey, cli.KeyID)
	}

	if len(cli.KeyUsage) > 0 {
		generatedKey.Set(jwk.KeyUsageKey, cli.KeyUsage)
	}

	if len(cli.KeyOps) > 0 {
		generatedKey.Set(jwk.KeyOpsKey, cli.KeyOps)
	}

	if len(cli.Algorithm) > 0 {
		generatedKey.Set(jwk.AlgorithmKey, cli.Algorithm)
	}

	return nil
}

// Run handles adding any common attributes to the key created by the subcommand.
// This method also handles writing the private key as requested by the CLI options.
func (cli *CommandLine) Run(k *kong.Kong, ctx *kong.Context, p *PublicOut, generatedKey jwk.Key) (err error) {
	var (
		outPath  string
		isAppend bool
	)

	err = cli.setAttributes(generatedKey)
	if err == nil {
		outPath, isAppend, err = cli.GeneratedOut.path()
	}

	if err == nil && p != nil {
		var (
			pubOutPath  string
			pubIsAppend bool
			pubKey      jwk.Key
		)

		pubOutPath, pubIsAppend, err = p.path()
		if err == nil && len(pubOutPath) > 0 {
			if pubOutPath == outPath {
				err = errors.New("Cannot use the same location for both the private and public keys")
			} else if pubKey, err = generatedKey.PublicKey(); err == nil {
				err = Writer{
					Stdout: k.Stdout,
					Stdin:  os.Stdin,
					Path:   pubOutPath,
					Append: pubIsAppend,
					Format: p.PubFormat,
				}.WriteKey(pubKey)
			}
		}
	}

	if err == nil {
		err = Writer{
			Stdout: k.Stdout,
			Stdin:  os.Stdin,
			Path:   outPath,
			Append: isAppend,
			Format: cli.GeneratedOut.Format,
		}.WriteKey(generatedKey)
	}

	return
}

func newParser() *kong.Kong {
	return kong.Must(
		new(CommandLine),
		kong.UsageOnError(),
		kong.Description("Generates JWK keys"),
	)
}

func run(parser *kong.Kong, args ...string) (err error) {
	var ctx *kong.Context
	ctx, err = parser.Parse(args)
	if err == nil {
		err = ctx.Run()
	}

	return
}
