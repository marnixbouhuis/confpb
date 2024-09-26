package scan_test

import (
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/marnixbouhuis/confpb/pkg/runtime/scan"
	"github.com/stretchr/testify/assert"
)

func TestInt32(t *testing.T) {
	type args struct {
		envKey      string
		environment map[string]string
	}
	tests := []*struct {
		name              string
		args              args
		expectedResult    int32
		expectedHasResult bool
		expectedErr       error
	}{
		{
			name: "reading a valid variable from environment (positive)",
			args: args{
				envKey: "FOO",
				environment: map[string]string{
					"FOO": "123",
				},
			},
			expectedResult:    123,
			expectedHasResult: true,
			expectedErr:       nil,
		},
		{
			name: "reading a valid variable from environment (negative)",
			args: args{
				envKey: "FOO",
				environment: map[string]string{
					"FOO": "-123",
				},
			},
			expectedResult:    -123,
			expectedHasResult: true,
			expectedErr:       nil,
		},
		{
			name: "reading an empty value from environment",
			args: args{
				envKey: "FOO",
				environment: map[string]string{
					"FOO": "",
				},
			},
			expectedResult:    0,
			expectedHasResult: true,
			expectedErr: fmt.Errorf("failed to process environment variable \"FOO\": invalid value \"\", unable to parse int32: %w", &strconv.NumError{
				Func: "ParseInt",
				Num:  "",
				Err:  errors.New("invalid syntax"),
			}),
		},
		{
			name: "environment variable missing",
			args: args{
				envKey:      "FOO",
				environment: map[string]string{},
			},
			expectedResult:    0,
			expectedHasResult: false,
			expectedErr:       nil,
		},
		{
			name: "reading an invalid number from environment",
			args: args{
				envKey: "FOO",
				environment: map[string]string{
					"FOO": "not-a-number",
				},
			},
			expectedResult:    0,
			expectedHasResult: true,
			expectedErr: fmt.Errorf("failed to process environment variable \"FOO\": invalid value \"not-a-number\", unable to parse int32: %w", &strconv.NumError{
				Func: "ParseInt",
				Num:  "not-a-number",
				Err:  errors.New("invalid syntax"),
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for k, v := range test.args.environment {
				t.Setenv(k, v)
			}

			result, hasResult, err := scan.Int32(test.args.envKey)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedHasResult, hasResult)
			assert.Equal(t, test.expectedErr, err)
		})
	}
}