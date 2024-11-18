package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/jsonschemagen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
	"github.com/stretchr/testify/require"
)

func TestSnapshot(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, jsonschemagen.GenerateFile, testDataFS, "testdata/e2e.proto")
	content := testutil.GetFileFromGenerationResult(t, res, "e2e.schema.json")

	expected, err := testDataFS.ReadFile("testdata/e2e.schema.json")
	require.NoError(t, err)
	require.Equal(t, string(expected), content)
}
