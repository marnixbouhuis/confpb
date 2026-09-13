package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/defaultgen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
)

func TestUint32Field(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/uint32.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := Uint32FromDefault()

			x := uint32(456)
			protoEqual(t, &Uint32{
				Normal: uint32(123),
				WithPresence: &x,
				List: []uint32{123, 456, 789},
				OneofTest: &Uint32_OneofOption{
					OneofOption: 100,
				},
				Map: map[uint32]uint32{
					12: 34,
					56: 78,
				},
			}, actual)
		}
	`)
}

func TestUint32Field2024(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/uint32_2024.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := Uint32FromDefault()

			withPresence := uint32(456)
			oneofOption := uint32(100)
			expected := Uint32_builder{
				Normal: uint32(123),
				WithPresence: &withPresence,
				List: []uint32{123, 456, 789},
				OneofOption: &oneofOption,
				Map: map[uint32]uint32{
					12: 34,
					56: 78,
				},
			}.Build()
			protoEqual(t, expected, actual)
		}
	`)
}
