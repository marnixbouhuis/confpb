package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/defaultgen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
)

func TestSfixed64Field(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/sfixed64.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := Sfixed64FromDefault()

			x := int64(456)
			protoEqual(t, &Sfixed64{
				Normal: int64(123),
				WithPresence: &x,
				List: []int64{123, 456, 789},
				OneofTest: &Sfixed64_OneofOption{
					OneofOption: 100,
				},
				Map: map[int64]int64{
					12: 34,
					56: 78,
				},
			}, actual)
		}
	`)
}

func TestSfixed64Field2024(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/sfixed64_2024.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := Sfixed64FromDefault()

			withPresence := int64(456)
			oneofOption := int64(100)
			expected := Sfixed64_builder{
				Normal: int64(123),
				WithPresence: &withPresence,
				List: []int64{123, 456, 789},
				OneofOption: &oneofOption,
				Map: map[int64]int64{
					12: 34,
					56: 78,
				},
			}.Build()
			protoEqual(t, expected, actual)
		}
	`)
}
