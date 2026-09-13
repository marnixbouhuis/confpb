package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/defaultgen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
)

func TestNoFieldsWithOption(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/no_fields.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestNoFields(t *testing.T) {
			t.Parallel()
			actual := NoFieldsWithDefaultOptionFromDefault()
			protoEqual(t, &NoFieldsWithDefaultOption{}, actual)
		}
	`)
}

func TestNoFieldsWithOption2024(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/no_fields_2024.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestNoFields(t *testing.T) {
			t.Parallel()
			actual := NoFieldsWithDefaultOptionFromDefault()
			protoEqual(t, NoFieldsWithDefaultOption_builder{}.Build(), actual)
		}
	`)
}
