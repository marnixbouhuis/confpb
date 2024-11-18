package jsonschemagen

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/marnixbouhuis/confpb/internal/codegen"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// JSONSchemaCore is a go struct that implements the structure defined in:
// https://github.com/json-schema-org/json-schema-spec/blob/0d2e45422eda1dd5d3eb76905cb816b612d63a5b/meta/core.json
type JSONSchemaCore struct {
	Schema        *string                `json:"$schema,omitempty"`
	ID            *string                `json:"$id,omitempty"`
	Ref           *string                `json:"$ref,omitempty"`
	Anchor        *string                `json:"$anchor,omitempty"`
	DynamicRef    *string                `json:"$dynamicRef,omitempty"`
	DynamicAnchor *string                `json:"$dynamicAnchor,omitempty"`
	Vocabulary    map[string]bool        `json:"$vocabulary,omitempty"`
	Comment       *string                `json:"$comment,omitempty"`
	Defs          map[string]*JSONSchema `json:"$defs,omitempty"`
}

// JSONSchemaMetaData is a go struct that implements the structure defined in:
// https://github.com/json-schema-org/json-schema-spec/blob/0d2e45422eda1dd5d3eb76905cb816b612d63a5b/meta/meta-data.json
type JSONSchemaMetaData struct {
	Title       *string       `json:"title,omitempty"`
	Description *string       `json:"description,omitempty"`
	Default     interface{}   `json:"default,omitempty"`
	Deprecated  *bool         `json:"deprecated,omitempty"`
	ReadOnly    *bool         `json:"readOnly,omitempty"`
	WriteOnly   *bool         `json:"writeOnly,omitempty"`
	Examples    []interface{} `json:"examples,omitempty"`
}

// JSONSchemaApplicator is a go struct that implements the structure defined in:
// https://github.com/json-schema-org/json-schema-spec/blob/0d2e45422eda1dd5d3eb76905cb816b612d63a5b/meta/applicator.json
type JSONSchemaApplicator struct {
	PrefixItems          []*JSONSchema          `json:"prefixItems,omitempty"`
	Items                *JSONSchema            `json:"items,omitempty"`
	Contains             *JSONSchema            `json:"contains,omitempty"`
	AdditionalProperties interface{}            `json:"additionalProperties,omitempty"`
	Properties           map[string]*JSONSchema `json:"properties,omitempty"`
	PatternProperties    map[string]*JSONSchema `json:"patternProperties,omitempty"`
	DependentProperties  map[string]*JSONSchema `json:"dependentProperties,omitempty"`
	PropertyNames        *JSONSchema            `json:"propertyNames,omitempty"`
	If                   *JSONSchema            `json:"if,omitempty"`
	Then                 *JSONSchema            `json:"then,omitempty"`
	Else                 *JSONSchema            `json:"else,omitempty"`
	AllOf                []*JSONSchema          `json:"allOf,omitempty"`
	AnyOf                []*JSONSchema          `json:"anyOf,omitempty"`
	OneOf                []*JSONSchema          `json:"oneOf,omitempty"`
	Not                  *JSONSchema            `json:"not,omitempty"`
}

// JSONSchemaUnevaluated is a go struct that implements the structure defined in:
// https://github.com/json-schema-org/json-schema-spec/blob/0d2e45422eda1dd5d3eb76905cb816b612d63a5b/meta/unevaluated.json
type JSONSchemaUnevaluated struct {
	UnevaluatedItems      *JSONSchema `json:"unevaluatedItems,omitempty"`
	UnevaluatedProperties *JSONSchema `json:"unevaluatedProperties,omitempty"`
}

// JSONSchemaValidation is a go struct that implements the structure defined in:
// https://github.com/json-schema-org/json-schema-spec/blob/0d2e45422eda1dd5d3eb76905cb816b612d63a5b/meta/validation.json
type JSONSchemaValidation struct {
	Type              []string            `json:"type,omitempty"` // This is technically a string OR an array, since we use this for code gen only it does not matter.
	Const             interface{}         `json:"const,omitempty"`
	Enum              []interface{}       `json:"enum,omitempty"`
	MultipleOf        *uint64             `json:"multipleOf,omitempty"`
	Maximum           *float64            `json:"maximum,omitempty"`
	ExclusiveMaximum  *float64            `json:"exclusiveMaximum,omitempty"`
	Minimum           *float64            `json:"minimum,omitempty"`
	ExclusiveMinimum  *float64            `json:"exclusiveMinimum,omitempty"`
	MaxLength         *uint64             `json:"maxLength,omitempty"`
	MinLength         *uint64             `json:"minLength,omitempty"`
	Pattern           *string             `json:"pattern,omitempty"`
	MaxItems          *uint64             `json:"maxItems,omitempty"`
	MinItems          *uint64             `json:"minItems,omitempty"`
	UniqueItems       *bool               `json:"uniqueItems,omitempty"`
	MaxContains       *uint64             `json:"maxContains,omitempty"`
	MinContains       *uint64             `json:"minContains,omitempty"`
	MaxProperties     *uint64             `json:"maxProperties,omitempty"`
	MinProperties     *uint64             `json:"minProperties,omitempty"`
	Required          []string            `json:"required,omitempty"`
	DependentRequired map[string][]string `json:"dependentRequired,omitempty"`
}

// JSONSchemaFormatAnnotation is a go struct that implements the structure defined in:
// https://github.com/json-schema-org/json-schema-spec/blob/0d2e45422eda1dd5d3eb76905cb816b612d63a5b/meta/format-annotation.json
type JSONSchemaFormatAnnotation struct {
	Format *string `json:"format,omitempty"`
}

// JSONSchemaContent is a go struct that implements the structure defined in:
// https://github.com/json-schema-org/json-schema-spec/blob/0d2e45422eda1dd5d3eb76905cb816b612d63a5b/meta/content.json
type JSONSchemaContent struct {
	ContentEncoding  *string     `json:"contentEncoding,omitempty"`
	ContentMediaType *string     `json:"contentMediaType,omitempty"`
	ContentSchema    *JSONSchema `json:"contentSchema,omitempty"`
}

// JSONSchema is a go struct that maps to a JSON schema document, defined in draft 2020-12:
// https://github.com/json-schema-org/json-schema-spec/blob/0d2e45422eda1dd5d3eb76905cb816b612d63a5b/schema.json
type JSONSchema struct {
	*JSONSchemaCore
	*JSONSchemaMetaData
	*JSONSchemaApplicator
	*JSONSchemaUnevaluated
	*JSONSchemaValidation
	*JSONSchemaFormatAnnotation
	*JSONSchemaContent
}

func ptr[T any](v T) *T {
	return &v
}

var _ codegen.FileGeneratorFunc = GenerateFile

func GenerateFile(plugin *protogen.Plugin, file *protogen.File) error {
	name, _ := os.Executable() // Ignore error, this is not critical
	name = filepath.Base(name)

	root := &JSONSchema{
		JSONSchemaCore: &JSONSchemaCore{
			Schema: ptr("https://json-schema.org/draft/2020-12/schema"),
			Defs:   make(map[string]*JSONSchema),
		},
		JSONSchemaMetaData: &JSONSchemaMetaData{
			Title:       ptr(string(file.Desc.FullName())),
			Description: ptr(fmt.Sprintf("Code generated by %s. DO NOT EDIT. Schema definitions for %s.", name, file.Desc.FullName())),
			Deprecated:  file.Proto.Options.Deprecated,
		},
		JSONSchemaApplicator: &JSONSchemaApplicator{
			OneOf: make([]*JSONSchema, 0),
		},
	}

	err := codegen.IterateMessages(file.Messages, func(message *protogen.Message) error {
		return processMessage(root, message)
	})
	if err != nil {
		return fmt.Errorf("failed to generate JSON schema: %w", err)
	}

	b, err := json.MarshalIndent(root, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshall JSON schema: %w", err)
	}

	fileName := file.GeneratedFilenamePrefix + ".schema.json"
	g := plugin.NewGeneratedFile(fileName, file.GoImportPath)
	g.P(string(b))

	return nil
}

func fieldToSchema(root *JSONSchema, field *protogen.Field) (*JSONSchema, error) {
	var isFieldDeprecated bool
	if opts, isOpts := field.Desc.Options().(*descriptorpb.FieldOptions); isOpts {
		isFieldDeprecated = opts.GetDeprecated()
	}

	schema := &JSONSchema{
		JSONSchemaMetaData: &JSONSchemaMetaData{
			Title:       ptr(string(field.Desc.FullName())),
			Description: ptr(field.Comments.Leading.String()),
			Deprecated:  &isFieldDeprecated,
		},
		JSONSchemaValidation: &JSONSchemaValidation{},
		JSONSchemaApplicator: &JSONSchemaApplicator{},
		JSONSchemaContent:    &JSONSchemaContent{},
	}

	// Handle map fields
	if field.Desc.IsMap() {
		keyType := field.Message.Fields[0]
		valueType := field.Message.Fields[1]

		// Create schema for map values
		valueSchema, err := fieldToSchema(root, valueType)
		if err != nil {
			return nil, fmt.Errorf("failed to create schema for map value type: %w", err)
		}

		// Maps are represented as objects in JSON
		schema.Type = []string{"object"}
		schema.AdditionalProperties = valueSchema

		// If the key type isn't string we need to add a pattern to validate the property names.
		// Possible key types according to https://protobuf.dev/reference/protobuf/proto3-spec/#map_field are:
		// keyType = "int32" | "int64" | "uint32" | "uint64" | "sint32" | "sint64" |
		//          "fixed32" | "fixed64" | "sfixed32" | "sfixed64" | "bool" | "string"
		//nolint:exhaustive // not all kinds can be used as map keys
		switch keyType.Desc.Kind() {
		case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
			schema.PropertyNames = &JSONSchema{
				JSONSchemaValidation: &JSONSchemaValidation{
					Pattern: ptr(`^-?([0-9]|[1-9][0-9]{1,9})$`), // -2147483648 to 2147483647
				},
			}
		case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
			schema.PropertyNames = &JSONSchema{
				JSONSchemaValidation: &JSONSchemaValidation{
					Pattern: ptr(`^([0-9]|[1-9][0-9]{1,9})$`), // 0 to 4294967295
				},
			}
		case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
			schema.PropertyNames = &JSONSchema{
				JSONSchemaValidation: &JSONSchemaValidation{
					Pattern: ptr(`^-?([0-9]|[1-9][0-9]{1,19})$`), // -9223372036854775808 to 9223372036854775807
				},
			}
		case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
			schema.PropertyNames = &JSONSchema{
				JSONSchemaValidation: &JSONSchemaValidation{
					Pattern: ptr(`^([0-9]|[1-9][0-9]{1,19})$`), // 0 to 18446744073709551615
				},
			}
		case protoreflect.BoolKind:
			schema.PropertyNames = &JSONSchema{
				JSONSchemaValidation: &JSONSchemaValidation{
					Pattern: ptr(`^(true|false)$`),
				},
			}
		}

		return schema, nil
	}

	switch field.Desc.Kind() {
	case protoreflect.BoolKind:
		schema.Type = []string{"boolean"}
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		schema.Type = []string{"integer"}
		schema.Minimum = ptr(float64(math.MinInt32))
		schema.Maximum = ptr(float64(math.MaxInt32))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		schema.Type = []string{"integer"}
		schema.Minimum = ptr(float64(0))
		schema.Maximum = ptr(float64(math.MaxUint32))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		schema.Type = []string{"integer"}
		schema.Minimum = ptr(float64(math.MinInt64))
		schema.Maximum = ptr(float64(math.MaxInt64))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		schema.Type = []string{"integer"}
		schema.Minimum = ptr(float64(0))
		schema.Maximum = ptr(float64(math.MaxUint64))
	case protoreflect.FloatKind:
		schema.Type = []string{"number"}
		schema.Minimum = ptr(math.SmallestNonzeroFloat32)
		schema.Maximum = ptr(math.MaxFloat32)
	case protoreflect.DoubleKind:
		schema.Type = []string{"number"}
		schema.Minimum = ptr(math.SmallestNonzeroFloat64)
		schema.Maximum = ptr(math.MaxFloat64)
	case protoreflect.StringKind:
		schema.Type = []string{"string"}
	case protoreflect.BytesKind:
		schema.Type = []string{"string"}
		schema.ContentEncoding = ptr("base64")
	case protoreflect.EnumKind:
		for _, val := range field.Enum.Values {
			var isValueDeprecated bool
			if opts, isOpts := val.Desc.Options().(*descriptorpb.EnumValueOptions); isOpts {
				isValueDeprecated = opts.GetDeprecated()
			}

			schema.OneOf = append(schema.OneOf, &JSONSchema{
				JSONSchemaValidation: &JSONSchemaValidation{
					Type:  []string{"string"},
					Const: string(val.Desc.Name()),
				},
				JSONSchemaMetaData: &JSONSchemaMetaData{
					Deprecated: &isValueDeprecated,
				},
			})
		}
	case protoreflect.MessageKind:
		switch field.Message.Desc.FullName() {
		case "google.protobuf.Timestamp":
			schema.Type = []string{"string"}
			// Match RFC3339 timestamp
			schema.Pattern = ptr(`^\d{4}-\d{2}-\d{2}T\d{2}%3A\d{2}%3A\d{2}(?:%2E\d+)?[A-Z]?(?:[.-](?:08%3A\d{2}|\d{2}[A-Z]))?$`)
		case "google.protobuf.Duration":
			schema.Type = []string{"string"}
			schema.Pattern = ptr("^-?([0-9]*[.])?[0-9]+(s)$") // Allow values like "3s", "-3s", "3.000000001s", "3.000001s"
		case "google.protobuf.Struct":
			schema.Type = []string{"object"}
			schema.AdditionalProperties = true
		case "google.protobuf.Value":
			// Match any value, specify no type
			schema.Type = nil
		default:
			// Regular message, make sure it's present in the Defs of the root schema
			messageName := string(field.Message.Desc.FullName())
			if _, hasDef := root.Defs[messageName]; !hasDef {
				if err := processMessage(root, field.Message); err != nil {
					return nil, fmt.Errorf("failed to generate schema for referenced message: %w", err)
				}
			}
			schema.AllOf = []*JSONSchema{{
				JSONSchemaCore: &JSONSchemaCore{
					Ref: ptr("#/$defs/" + messageName),
				},
			}}
		}
	case protoreflect.GroupKind:
		// No support needed since we the minimum proto version that we support is proto3.
		return nil, errors.New("groups are not supported")
	}

	if field.Desc.IsList() {
		return &JSONSchema{
			JSONSchemaValidation: &JSONSchemaValidation{
				Type: []string{"array"},
			},
			JSONSchemaApplicator: &JSONSchemaApplicator{
				Items: schema,
			},
		}, nil
	}

	return schema, nil
}

func processMessage(root *JSONSchema, message *protogen.Message) error {
	name := string(message.Desc.FullName())

	var isMessageDeprecated bool
	if opts, isOpts := message.Desc.Options().(*descriptorpb.MessageOptions); isOpts {
		isMessageDeprecated = opts.GetDeprecated()
	}

	schema := &JSONSchema{
		JSONSchemaMetaData: &JSONSchemaMetaData{
			Title:       ptr(string(message.Desc.FullName())),
			Description: ptr(message.Comments.Leading.String()),
			Deprecated:  &isMessageDeprecated,
		},
		JSONSchemaValidation: &JSONSchemaValidation{
			Type: []string{"object"},
		},
		JSONSchemaApplicator: &JSONSchemaApplicator{
			Properties:           make(map[string]*JSONSchema),
			AdditionalProperties: false,
		},
	}

	// Before processing any fields, store a reference of the schema in the defs, otherwise we get into infinite loops
	// when processing circular dependent messages
	root.Defs[name] = schema

	oneofFieldGroups := make(map[string][]*JSONSchema)
	for _, field := range message.Fields {
		if field.Desc.IsWeak() {
			return fmt.Errorf("field \"%s\" is invalid, weak fields are not supported", field.Desc.FullName())
		}

		fieldSchema, err := fieldToSchema(root, field)
		if err != nil {
			return fmt.Errorf("failed to convert field \"%s\" to schema: %w", field.Desc.FullName(), err)
		}

		if field.Oneof == nil {
			// Not part of oneof group, add it to the schema properties directly
			schema.Properties[field.Desc.JSONName()] = fieldSchema
			continue
		}

		// Field is part of oneof group
		oneof, hasOneof := oneofFieldGroups[field.Oneof.GoName]
		if !hasOneof {
			oneof = make([]*JSONSchema, 0, 1)
		}
		oneof = append(oneof, &JSONSchema{
			JSONSchemaValidation: &JSONSchemaValidation{
				Type: []string{"object"},
			},
			JSONSchemaApplicator: &JSONSchemaApplicator{
				Properties: map[string]*JSONSchema{
					field.Desc.JSONName(): fieldSchema,
				},
			},
		})
		oneofFieldGroups[field.Oneof.GoName] = oneof
	}

	// Add oneof groups to schema in sorted order, this way we ensure we have a stable JSON output
	oneofNames := make([]string, 0, len(oneofFieldGroups))
	for name := range oneofFieldGroups {
		oneofNames = append(oneofNames, name)
	}
	sort.Strings(oneofNames)

	for _, oneofName := range oneofNames {
		schema.OneOf = append(schema.OneOf, oneofFieldGroups[oneofName]...)
	}

	// Register configuration file format for message in root schema.
	root.OneOf = append(root.OneOf, &JSONSchema{
		JSONSchemaMetaData: &JSONSchemaMetaData{
			Title:       ptr(fmt.Sprintf("Configuration file format for: %s.", name)),
			Description: ptr(message.Comments.Leading.String()),
			Deprecated:  &isMessageDeprecated,
		},
		JSONSchemaValidation: &JSONSchemaValidation{
			Type:     []string{"object"},
			Required: []string{"@type"},
		},
		JSONSchemaApplicator: &JSONSchemaApplicator{
			Properties: map[string]*JSONSchema{
				"@type": {
					JSONSchemaValidation: &JSONSchemaValidation{
						Type:  []string{"string"},
						Const: "type.googleapis.com/" + name,
					},
				},
			},
			AdditionalProperties: false,
			AllOf: []*JSONSchema{{
				JSONSchemaCore: &JSONSchemaCore{
					Ref: ptr("#/$defs/" + name),
				},
			}},
		},
	})

	return nil
}
