package e2e_test

import (
	"testing"

	"github.com/marnixbouhuis/confpb/internal/codegen/defaultgen"
	"github.com/marnixbouhuis/confpb/internal/codegen/testutil"
)

func TestMessageField(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/message.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := NestedFromDefault()

			protoEqual(t, &Nested{
				Normal: &Message{Test: "foo"},
				DontFill: &Message{},
				WithPresence: &Message{Test: "foo"},
				List: []*Message{{
					Test: "foo",
				}, {
					// No defaults filled
				}, {
					Test: "foo",
				}},
				OneofTest: &Nested_OneofOption{
					OneofOption: &Message{Test: "foo"},
				},
				Map: map[string]*Message{
					"key1": &Message{Test: "foo"},
					"key2": &Message{},
					"key3": &Message{Test: "foo"},
				},
			}, actual)
		}

		func TestEmbeddedMessageDefaults(t *testing.T) {
			t.Parallel()
			actual := WithEmbeddedFromDefault()

			protoEqual(t, &WithEmbedded{
				Normal: &WithEmbedded_EmbeddedMessage{Test: "foo"},
				DontFill: &WithEmbedded_EmbeddedMessage{},
				WithPresence: &WithEmbedded_EmbeddedMessage{Test: "foo"},
				List: []*WithEmbedded_EmbeddedMessage{{
					Test: "foo",
				}, {
					// No defaults filled
				}, {
					Test: "foo",
				}},
				OneofTest: &WithEmbedded_OneofOption{
					OneofOption: &WithEmbedded_EmbeddedMessage{Test: "foo"},
				},
				Map: map[string]*WithEmbedded_EmbeddedMessage{
					"key1": {Test: "foo"},
					"key2": {},
					"key3": {Test: "foo"},
				},
			}, actual)
		}
	`)
}

func TestMessageField2024(t *testing.T) {
	t.Parallel()

	res := testutil.RunGeneratorForFiles(t, defaultgen.GenerateFile, testDataFS, "testdata/message_2024.proto")
	testutil.RunTestInE2ERunner(t, res, `
		package main

		import (
			"testing"
		)

		func TestDefaults(t *testing.T) {
			t.Parallel()
			actual := NestedFromDefault()

			expected := Nested_builder{
				Normal: Message_builder{Test: "foo"}.Build(),
				DontFill: Message_builder{}.Build(),
				WithPresence: Message_builder{Test: "foo"}.Build(),
				List: []*Message{
					Message_builder{Test: "foo"}.Build(),
					Message_builder{}.Build(),
					Message_builder{Test: "foo"}.Build(),
				},
				OneofOption: Message_builder{Test: "foo"}.Build(),
				Map: map[string]*Message{
					"key1": Message_builder{Test: "foo"}.Build(),
					"key2": Message_builder{}.Build(),
					"key3": Message_builder{Test: "foo"}.Build(),
				},
			}.Build()
			protoEqual(t, expected, actual)
		}

		func TestEmbeddedMessageDefaults(t *testing.T) {
			t.Parallel()
			actual := WithEmbeddedFromDefault()

			expected := WithEmbedded_builder{
				Normal: WithEmbedded_EmbeddedMessage_builder{Test: "foo"}.Build(),
				DontFill: WithEmbedded_EmbeddedMessage_builder{}.Build(),
				WithPresence: WithEmbedded_EmbeddedMessage_builder{Test: "foo"}.Build(),
				List: []*WithEmbedded_EmbeddedMessage{
					WithEmbedded_EmbeddedMessage_builder{Test: "foo"}.Build(),
					WithEmbedded_EmbeddedMessage_builder{}.Build(),
					WithEmbedded_EmbeddedMessage_builder{Test: "foo"}.Build(),
				},
				OneofOption: WithEmbedded_EmbeddedMessage_builder{Test: "foo"}.Build(),
				Map: map[string]*WithEmbedded_EmbeddedMessage{
					"key1": WithEmbedded_EmbeddedMessage_builder{Test: "foo"}.Build(),
					"key2": WithEmbedded_EmbeddedMessage_builder{}.Build(),
					"key3": WithEmbedded_EmbeddedMessage_builder{Test: "foo"}.Build(),
				},
			}.Build()
			protoEqual(t, expected, actual)
		}
	`)
}
