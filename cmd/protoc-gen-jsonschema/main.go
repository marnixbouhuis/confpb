package main

import (
	"github.com/marnixbouhuis/confpb/internal/codegen"
	"github.com/marnixbouhuis/confpb/internal/codegen/jsonschemagen"
)

func main() {
	codegen.RunProtocPlugin(jsonschemagen.GenerateFile)
}
