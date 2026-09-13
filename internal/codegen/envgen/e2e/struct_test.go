package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/envgen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
)

func TestStructField(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, envgen.GenerateFile, testDataFS, "testdata/struct.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (		
			"github.com/stretchr/testify/assert"
			"github.com/stretchr/testify/require"
			"google.golang.org/protobuf/types/known/structpb"
			"testing"
		)

		func TestNormalField(t *testing.T) {
			t.Setenv("STRUCT", "{\"some\": \"json\"}")

			actual, err := StructFromEnv()
			require.NoError(t, err)

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
			}, actual)
		}

		func TestPresenceField(t *testing.T) {
			t.Setenv("STRUCT_WITH_PRESENCE", "{\"some\": \"json\"}")

			actual, err := StructFromEnv()
			require.NoError(t, err)

			protoEqual(t, &Struct{
				WithPresence: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"some": {
							Kind: &structpb.Value_StringValue{
								StringValue: "json",
							},
						},
					},
				},
			}, actual)
		}

		func TestList(t *testing.T) {
			t.Setenv("STRUCT_LIST_1", "{\"item\": \"item1\"}")
			t.Setenv("STRUCT_LIST_2", "{\"item\": \"item2\"}")

			actual, err := StructFromEnv()
			require.NoError(t, err)

			protoEqual(t, &Struct{
				List: []*structpb.Struct{{
					Fields: map[string]*structpb.Value{
						"item": {
							Kind: &structpb.Value_StringValue{
								StringValue: "item1",
							},
						},
					},
				}, {
					Fields: map[string]*structpb.Value{
						"item": {
							Kind: &structpb.Value_StringValue{
								StringValue: "item2",
							},
						},
					},
				}},
			}, actual)
		}

		func TestOneOfOneOptionSet(t *testing.T) {
			t.Setenv("STRUCT_ONEOF_A", "{\"some\": \"json\"}")

			actual, err := StructFromEnv()
			require.NoError(t, err)

			protoEqual(t, &Struct{
				OneofTest: &Struct_OneofOptionA{
					OneofOptionA: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"some": {
								Kind: &structpb.Value_StringValue{
									StringValue: "json",
								},
							},
						},
					},
				},
			}, actual)
		}

		func TestOneOfMultipleSet(t *testing.T) {
			t.Setenv("STRUCT_ONEOF_A", "{\"some\": \"json\"}")
			t.Setenv("STRUCT_ONEOF_B", "{\"some\": \"json\"}")

			actual, err := StructFromEnv()
			assert.Error(t, err)
			assert.Nil(t, actual)
		}
	`)
}

func TestStructField2024(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, envgen.GenerateFile, testDataFS, "testdata/struct_2024.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"github.com/stretchr/testify/assert"
			"github.com/stretchr/testify/require"
			"google.golang.org/protobuf/types/known/structpb"
			"testing"
		)

		func mkStruct(k, v string) *structpb.Struct {
			return &structpb.Struct{
				Fields: map[string]*structpb.Value{
					k: {Kind: &structpb.Value_StringValue{StringValue: v}},
				},
			}
		}

		func TestNormalField(t *testing.T) {
			t.Setenv("STRUCT", "{\"some\": \"json\"}")

			actual, err := StructFromEnv()
			require.NoError(t, err)

			protoEqual(t, Struct_builder{
				Normal: mkStruct("some", "json"),
			}.Build(), actual)
		}

		func TestPresenceField(t *testing.T) {
			t.Setenv("STRUCT_WITH_PRESENCE", "{\"some\": \"json\"}")

			actual, err := StructFromEnv()
			require.NoError(t, err)

			protoEqual(t, Struct_builder{
				WithPresence: mkStruct("some", "json"),
			}.Build(), actual)
		}

		func TestList(t *testing.T) {
			t.Setenv("STRUCT_LIST_1", "{\"item\": \"item1\"}")
			t.Setenv("STRUCT_LIST_2", "{\"item\": \"item2\"}")

			actual, err := StructFromEnv()
			require.NoError(t, err)

			protoEqual(t, Struct_builder{
				List: []*structpb.Struct{
					mkStruct("item", "item1"),
					mkStruct("item", "item2"),
				},
			}.Build(), actual)
		}

		func TestOneOfOneOptionSet(t *testing.T) {
			t.Setenv("STRUCT_ONEOF_A", "{\"some\": \"json\"}")

			actual, err := StructFromEnv()
			require.NoError(t, err)

			protoEqual(t, Struct_builder{
				OneofOptionA: mkStruct("some", "json"),
			}.Build(), actual)
		}

		func TestOneOfMultipleSet(t *testing.T) {
			t.Setenv("STRUCT_ONEOF_A", "{\"some\": \"json\"}")
			t.Setenv("STRUCT_ONEOF_B", "{\"some\": \"json\"}")

			actual, err := StructFromEnv()
			assert.Error(t, err)
			assert.Nil(t, actual)
		}
	`)
}
