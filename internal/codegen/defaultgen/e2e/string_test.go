package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/defaultgen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
)

func TestStringField(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/string.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := StringFromDefault()

			x := "bar"
			protoEqual(t, &String{
				Normal: "foo",
				WithPresence: &x,
				List: []string{"foo", "bar", "baz"},
				OneofTest: &String_OneofOption{
					OneofOption: "qux",
				},
				Map: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			}, actual)
		}
	`)
}

func TestStringField2024(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/string_2024.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := StringFromDefault()

			withPresence := "bar"
			oneofOption := "qux"
			expected := String_builder{
				Normal: "foo",
				WithPresence: &withPresence,
				List: []string{"foo", "bar", "baz"},
				OneofOption: &oneofOption,
				Map: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			}.Build()
			protoEqual(t, expected, actual)
		}
	`)
}
