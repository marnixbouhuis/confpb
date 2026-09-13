package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/defaultgen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
)

func TestDoubleField(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/double.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := DoubleFromDefault()

			x := float64(456)
			protoEqual(t, &Double{
				Normal: float64(123),
				WithPresence: &x,
				List: []float64{123, 456, 789},
				OneofTest: &Double_OneofOption{
					OneofOption: 100,
				},
				Map: map[string]float64{
					"key1": 34,
					"key2": 78,
				},
			}, actual)
		}
	`)
}

func TestDoubleField2024(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/double_2024.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := DoubleFromDefault()

			withPresence := float64(456)
			oneofOption := float64(100)
			expected := Double_builder{
				Normal: float64(123),
				WithPresence: &withPresence,
				List: []float64{123, 456, 789},
				OneofOption: &oneofOption,
				Map: map[string]float64{
					"key1": 34,
					"key2": 78,
				},
			}.Build()
			protoEqual(t, expected, actual)
		}
	`)
}
