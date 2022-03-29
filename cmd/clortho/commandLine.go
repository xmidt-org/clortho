package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
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
	Curve string `name:"crv" default:"P-256" enum:"P-256,P-384,P-521" help:"the elliptic curve to use"`
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
	RSA RSA `cmd:"" name:"RSA"`
	EC  EC  `cmd:"" name:"EC"`
	Oct Oct `cmd:"" name:"oct"`
	OKP OKP `cmd:"" name:"OKP"`

	KeyID      string     `name:"kid" help:"the key id"`
	KeyUsage   string     `name:"use" help:"the intended usage for the key, e.g. sig or enc"`
	Attributes Attributes `help:"additional, nonstandard attributes.  supplying any standard JWK attributes results in an error.  values that parse as numbers as added as such.  values enclosed in single quotes are always added as strings."`

	Seed int64 `help:"the RNG seed for key generation, used primarily for testing with consistent output.  DO NOT USE FOR PRODUCTION KEYS."`
}

func (cli *CommandLine) AfterApply(ctx *kong.Context) error {
	if cli.Seed != 0 {
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

func (cli *CommandLine) Run(ctx *kong.Context, generatedKey jwk.Key) error {
	if err := cli.Attributes.SetTo(generatedKey); err != nil {
		return err
	}

	if len(cli.KeyID) > 0 {
		generatedKey.Set(jwk.KeyIDKey, cli.KeyID)
	}

	if len(cli.KeyUsage) > 0 {
		generatedKey.Set(jwk.KeyUsageKey, cli.KeyUsage)
	}

	data, err := json.MarshalIndent(generatedKey, "", "\t")
	if err != nil {
		return err
	}

	_, err = ctx.Stdout.Write(data)
	return err
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
