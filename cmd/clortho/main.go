package main

import (
	"os"
)

func main() {
	parser := newParser()
	parser.FatalIfErrorf(
		run(parser, os.Args[1:]...),
	)
}
