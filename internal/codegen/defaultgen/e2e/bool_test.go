package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/defaultgen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
)

func TestBoolField(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/bool.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := BoolFromDefault()

			x := true
			protoEqual(t, &Bool{
				Normal: true,
				WithPresence: &x,
				List: []bool{true, false, true},
				OneofTest: &Bool_OneofOption{
					OneofOption: true,
				},
				Map: map[bool]bool{
					false: true,
					true: false,
				},
			}, actual)
		}
	`)
}

func TestBoolField2024(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/bool_2024.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := BoolFromDefault()

			withPresence := true
			oneofOption := true
			expected := Bool_builder{
				Normal: true,
				WithPresence: &withPresence,
				List: []bool{true, false, true},
				OneofOption: &oneofOption,
				Map: map[bool]bool{
					false: true,
					true: false,
				},
			}.Build()
			protoEqual(t, expected, actual)
		}
	`)
}
