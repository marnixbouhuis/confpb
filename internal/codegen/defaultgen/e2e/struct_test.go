package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/defaultgen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
)

func TestStructField(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/struct.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"google.golang.org/protobuf/types/known/structpb"
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := StructFromDefault()
			protoEqual(t, &Struct{
				Normal: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"some": {
							Kind: &structpb.Value_StringValue{
								StringValue: "json",
							},
						},
					},
				},
				WithPresence: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"some": {
							Kind: &structpb.Value_StringValue{
								StringValue: "json",
							},
						},
					},
				},
				List: []*structpb.Struct{
					&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"item": {
								Kind: &structpb.Value_StringValue{
									StringValue: "item1",
								},
							},
						},
					},
					&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"item": {
								Kind: &structpb.Value_StringValue{
									StringValue: "item2",
								},
							},
						},
					},
				},
				OneofTest: &Struct_OneofOption{
					OneofOption: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"some": {
								Kind: &structpb.Value_StringValue{
									StringValue: "json",
								},
							},
						},
					},
				},
				Map: map[string]*structpb.Struct{
					"key1": &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"item": {
								Kind: &structpb.Value_StringValue{
									StringValue: "item1",
								},
							},
						},
					},
					"key2": &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"item": {
								Kind: &structpb.Value_StringValue{
									StringValue: "item2",
								},
							},
						},
					},
				},
			}, actual)
		}
	`)
}

func TestStructField2024(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/struct_2024.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"google.golang.org/protobuf/types/known/structpb"
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := StructFromDefault()

			mkStruct := func(k, v string) *structpb.Struct {
				return &structpb.Struct{
					Fields: map[string]*structpb.Value{
						k: {Kind: &structpb.Value_StringValue{StringValue: v}},
					},
				}
			}

			expected := Struct_builder{
				Normal: mkStruct("some", "json"),
				WithPresence: mkStruct("some", "json"),
				List: []*structpb.Struct{
					mkStruct("item", "item1"),
					mkStruct("item", "item2"),
				},
				OneofOption: mkStruct("some", "json"),
				Map: map[string]*structpb.Struct{
					"key1": mkStruct("item", "item1"),
					"key2": mkStruct("item", "item2"),
				},
			}.Build()
			protoEqual(t, expected, actual)
		}
	`)
}
