package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	mrand "math/rand"
	"os"

	"github.com/alecthomas/kong"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/x25519"
)

// PublicOut is the common set of command flags that control how the public portion
// of the generated key is written.  By default, the public key isn't written separately.
type PublicOut struct {
	PubOutput string `placeholder:"FILE" xor:"pub-output,pub-append" help:"file to output the public portion of the generated key.  '-' indicates stdout.  if neither --pub-output nor --pub-append are specified, the public key will not be written separately.  this cannot refer to the same location as the generated private key."`
	PubAppend string `placeholder:"FILE" xor:"pub-output,pub-append" help:"file to which the generated public key will be appended.  '-' indicates reading public keys from stdin, appending the generated public key, then writing out the set to stdout.  this cannot refer to the same location as the generated private key."`
	PubFormat string `placeholder:"FORMAT" enum:"jwk,jwk-set,pem" default:"jwk-set" help:"the output format for the public key, one of pem, jwk, or jwk-set.  if not supplied, the output format will be detected from the output file suffix or, if output is going to stdout, the format of the keys being appended to (if any).  jwk-set is used if no format can be detected."`
}

func (out PublicOut) newPublicPipe(stdin io.Reader, stdout io.Writer) (PublicPipe, error) {
	return NewPublicPipe(
		stdin,
		stdout,
		out.PubAppend,
		out.PubOutput,
	)
}

// PrivateOut is the common flags governing how a generated private key is output.  By default, output
// is sent to stdout and the format is jwk-set.
type PrivateOut struct {
	Output string `placeholder:"FILE" short:"o" xor:"output,append" help:"file to output the generated key.  '-' indicates stdout, which is the default."`
	Append string `placeholder:"FILE" short:"a" xor:"output,append" help:"file to append the generated key.  '-' indicates reading keys from stdin, appending the generated key, then writing the resulting set to stdout."`
	Format string `placeholder:"FORMAT" short:"f" enum:"jwk,jwk-set,pem" default:"jwk-set" help:"the output format for the generated private key, one of pem, jwk, or jwk-set.  if not supplied, the output format will be detected from the output file suffix or, if output is going to stdout, the format of the keys being appended to (if any).  jwk-set is used if no format can be detected."`
}

func (out PrivateOut) newPipe(stdin io.Reader, stdout io.Writer) (Pipe, error) {
	return NewPipe(
		stdin,
		stdout,
		out.Append,
		out.Output,
	)
}

// PrivateOutNoPEM is a variant of PrivateOut for key commands that do not allow PEM formats.
// Oct and OKP keys may not be output as PEM.
type PrivateOutNoPEM struct {
	Output string `placeholder:"FILE" short:"o" xor:"output,append" help:"file to output the generated key.  '-' indicates stdout, which is the default."`
	Append string `placeholder:"FILE" short:"a" xor:"output,append" help:"file to append the generated key.  '-' indicates reading keys from stdin, appending the generated key, then writing the resulting set to stdout."`
	Format string `placeholder:"FORMAT" short:"f" enum:"jwk,jwk-set" default:"jwk-set" help:"the output format for the generated private key, either jwk or jwk-set.  if not supplied, the output format will be detected from the output file suffix or, if output is going to stdout, the format of the keys being appended to (if any).  jwk-set is used if no format can be detected."`
}

func (out PrivateOutNoPEM) newPipe(stdin io.Reader, stdout io.Writer) (Pipe, error) {
	return NewPipe(
		stdin,
		stdout,
		out.Append,
		out.Output,
	)
}

// RSA holds the command line options for generating RSA keys.
type RSA struct {
	Size       uint       `short:"s" default:"256" help:"the size of the key to generate, in bits"`
	PrivateOut PrivateOut `embed:""`
	PublicOut  PublicOut  `embed:""`
}

func (r *RSA) newKeyGenerator(random io.Reader) KeyGenerator {
	return KeyGenerator(func() (interface{}, error) {
		return rsa.GenerateKey(random, int(r.Size))
	})
}

// AfterApply generates the RSA key and binds it to the kong context.
func (r *RSA) AfterApply(k *kong.Kong, ctx *kong.Context, random io.Reader) error {
	ctx.Bind(r.newKeyGenerator(random))

	p, err := r.PrivateOut.newPipe(os.Stdin, k.Stdout)
	if err != nil {
		return err
	}

	ctx.Bind(p)

	pp, err := r.PublicOut.newPublicPipe(os.Stdin, k.Stdout)
	if err != nil {
		return err
	}

	ctx.Bind(pp)
	return nil
}

// EC holds the command line options for generating elliptic curve keys.
type EC struct {
	Curve      string     `name:"crv" default:"P-256" enum:"P-256,P-384,P-521" help:"the elliptic curve to use"`
	PrivateOut PrivateOut `embed:""`
	PublicOut  PublicOut  `embed:""`
}

// AfterApply generates the EC key and binds it to the kong context.
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
	Size       uint            `short:"s" default:"256" help:"the size of the key to generate, in bits"`
	PrivateOut PrivateOutNoPEM `embed:""`
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
	Curve      string          `name:"crv" default:"Ed25519" enum:"Ed25519,X25519" help:"the elliptic curve to use"`
	PrivateOut PrivateOutNoPEM `embed:""`
	PublicOut  PublicOut       `embed:""`
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

// CommandLine is the main command line driver.
type CommandLine struct {
	RSA RSA `cmd:"" name:"RSA" help:"Generates RSA keys"`
	EC  EC  `cmd:"" name:"EC" help:"Generates elliptic curve keys"`
	Oct Oct `cmd:"" name:"oct" help:"Generates symmetric keys"`
	OKP OKP `cmd:"" name:"OKP" help:"generates elliptic curve edwards or montgomery keys"`

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
func (cli *CommandLine) Run(k *kong.Kong, ctx *kong.Context, pipe *Pipe, ppipe *PublicPipe, generatedKey jwk.Key) error {
	if err := cli.setAttributes(generatedKey); err != nil {
		return err
	}

	return nil
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
