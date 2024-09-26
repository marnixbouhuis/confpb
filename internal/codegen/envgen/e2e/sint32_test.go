package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/envgen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
)

func TestSint32Field(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, envgen.GenerateFile, testDataFS, "testdata/sint32.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"github.com/stretchr/testify/assert"
			"github.com/stretchr/testify/require"
			"testing"
		)

		func TestNormalField(t *testing.T) {
			t.Setenv("SINT32", "123")

			actual, err := Sint32FromEnv()
			require.NoError(t, err)

			protoEqual(t, &Sint32{
				Normal: 123,
			}, actual)
		}

		func TestPresenceField(t *testing.T) {
			t.Setenv("SINT32_WITH_PRESENCE", "123")

			actual, err := Sint32FromEnv()
			require.NoError(t, err)

			expectedValue := int32(123)
			protoEqual(t, &Sint32{
				WithPresence: &expectedValue,
			}, actual)
		}

		func TestList(t *testing.T) {
			t.Setenv("SINT32_LIST_1", "123")
			t.Setenv("SINT32_LIST_2", "-123")
			t.Setenv("SINT32_LIST_3", "987654321")

			actual, err := Sint32FromEnv()
			require.NoError(t, err)

			protoEqual(t, &Sint32{
				List: []int32{123, -123, 987654321},
			}, actual)
		}

		func TestOneOfOneOptionSet(t *testing.T) {
			t.Setenv("SINT32_ONEOF_A", "123")

			actual, err := Sint32FromEnv()
			require.NoError(t, err)

			protoEqual(t, &Sint32{
				OneofTest: &Sint32_OneofOptionA{
					OneofOptionA: 123,
				},
			}, actual)
		}

		func TestOneOfMultipleSet(t *testing.T) {
			t.Setenv("SINT32_ONEOF_A", "123")
			t.Setenv("SINT32_ONEOF_B", "123")

			actual, err := Sint32FromEnv()
			assert.Error(t, err)
			assert.Nil(t, actual)
		}
	`)
}