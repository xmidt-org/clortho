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
	"io/fs"
	mrand "math/rand"

	"github.com/alecthomas/kong"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/x25519"
)

type RSA struct {
	Size uint `short:"s" default:"256" help:"the size of the key to generate, in bits"`
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
	return nil
}

type EC struct {
	Curve  string `name:"crv" default:"P-256" enum:"P-256,P-384,P-521" help:"the elliptic curve to use"`
	Public string `help:"the output file for the public key.  if not supplied, the public key is not output separately.  if --format was not supplied, the format is deduced from this file's extension."`
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
	return nil
}

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
	return nil
}

type OKP struct {
	Curve string `name:"crv" default:"Ed25519" enum:"Ed25519,X25519" help:"the elliptic curve to use"`
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

	return
}

type CommandLine struct {
	RSA RSA `cmd:"" name:"RSA" help:"Generates RSA keys"`
	EC  EC  `cmd:"" name:"EC"`
	Oct Oct `cmd:"" name:"oct"`
	OKP OKP `cmd:"" name:"OKP"`

	KeyID      string     `name:"kid" help:"the key id"`
	KeyUsage   string     `name:"use" help:"the intended usage for the key, e.g. sig or enc"`
	KeyOps     []string   `name:"key_ops" help:"the set of key operations.  duplicate values are not allowed."`
	Algorithm  string     `name:"alg" help:"the algorithm the generated key is intended to be used with."`
	Attributes Attributes `help:"additional, nonstandard attributes.  supplying any standard JWK attributes results in an error.  values that parse as numbers as added as such.  values enclosed in single quotes are always added as strings."`

	Output string `short:"o" xor:"output,append" placeholder:"FILE" help:"file to write the generated key.  '-' indicates stdout, which is also used if neither --output or --append is supplied.  if this is a system file, it will be created or overwritten as needed."`
	Append string `short:"a" xor:"output,append" placeholder:"FILE" help:"file to which the generated key is appended.  this file must exist and cannot be stdout."`
	Format string `short:"f" placeholder:"FORMAT" enum:"pem,jwk,jwk-set" default:"jwk" help:"the output format of the key, which will be a jwk-set by default. even if jwk is used, a jwk-set will still be output if the generated key is appended to any --in sources."`

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

	var set jwk.Set
	if len(cli.Append) > 0 {
		var err error
		set, err = ReadSetFile(cli.Append)

		// treat nonexistent files for appending as if they were simply empty
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	if set == nil {
		set = jwk.NewSet()
	}

	ctx.BindTo(
		set,
		(*jwk.Set)(nil),
	)

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
func (cli *CommandLine) Run(k *kong.Kong, ctx *kong.Context, set jwk.Set, generatedKey jwk.Key) error {
	if err := cli.setAttributes(generatedKey); err != nil {
		return err
	}

	set.Add(generatedKey)

	switch {
	case len(cli.Append) > 0:
		return WriteSetFile(set, cli.Format, cli.Append)

	case IsFile(cli.Output):
		return WriteSetFile(set, cli.Format, cli.Output)

	default:
		return WriteSet(set, cli.Format, k.Stdout)
	}
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
