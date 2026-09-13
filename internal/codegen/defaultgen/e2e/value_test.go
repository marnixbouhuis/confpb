package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/defaultgen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
)

func TestValueField(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/value.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"google.golang.org/protobuf/types/known/structpb"
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := ValueFromDefault()
			protoEqual(t, &Value{
				Normal: &structpb.Value{
					Kind: &structpb.Value_NumberValue{
						NumberValue: 123,
					},
				},
				WithPresence: &structpb.Value{
					Kind: &structpb.Value_NumberValue{
						NumberValue: 123,
					},
				},
				List: []*structpb.Value{
					&structpb.Value{
						Kind: &structpb.Value_NumberValue{
							NumberValue: 123,
						},
					},
					&structpb.Value{
						Kind: &structpb.Value_NullValue{
							NullValue: structpb.NullValue_NULL_VALUE,
						},
					},
					&structpb.Value{
						Kind: &structpb.Value_StringValue{
							StringValue: "some-string",
						},
					},
				},
				OneofTest: &Value_OneofOption{
					OneofOption: &structpb.Value{
						Kind: &structpb.Value_NumberValue{
							NumberValue: 123,
						},
					},
				},
				Map: map[string]*structpb.Value{
					"key1": &structpb.Value{
						Kind: &structpb.Value_NumberValue{
							NumberValue: 123,
						},
					},
					"key2": &structpb.Value{
						Kind: &structpb.Value_BoolValue{
							BoolValue: true,
						},
					},
					"key3": &structpb.Value{
						Kind: &structpb.Value_BoolValue{
							BoolValue: false,
						},
					},
				},
			}, actual)
		}
	`)
}

func TestValueField2024(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/value_2024.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"google.golang.org/protobuf/types/known/structpb"
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := ValueFromDefault()

			numberValue := func(n float64) *structpb.Value {
				return &structpb.Value{Kind: &structpb.Value_NumberValue{NumberValue: n}}
			}
			nullValue := func() *structpb.Value {
				return &structpb.Value{Kind: &structpb.Value_NullValue{NullValue: structpb.NullValue_NULL_VALUE}}
			}
			stringValue := func(s string) *structpb.Value {
				return &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: s}}
			}
			boolValue := func(b bool) *structpb.Value {
				return &structpb.Value{Kind: &structpb.Value_BoolValue{BoolValue: b}}
			}

			expected := Value_builder{
				Normal: numberValue(123),
				WithPresence: numberValue(123),
				List: []*structpb.Value{
					numberValue(123),
					nullValue(),
					stringValue("some-string"),
				},
				OneofOption: numberValue(123),
				Map: map[string]*structpb.Value{
					"key1": numberValue(123),
					"key2": boolValue(true),
					"key3": boolValue(false),
				},
			}.Build()
			protoEqual(t, expected, actual)
		}
	`)
}
