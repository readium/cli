package inspector

import (
	"github.com/readium/go-toolkit/pkg/manifest"
)

// setInferredA11y sets a single key of the inferred accessibility object stored
// in the metadata's OtherMetadata, creating the object when there is none.
//
// The object's other keys are left as they are. It can hold keys that
// [manifest.A11y] doesn't model, such as the inferred languages, so it must not
// be rewritten from an A11y: that would drop them.
//
// The value has to be in the form decoded JSON takes, like the rest of the
// object: [manifest.Metadata.InferredAccessibility] reads nothing else. For a
// list, that's what [jsonStrings] returns.
func setInferredA11y(metadata *manifest.Metadata, key string, value any) {
	inferred, ok := metadata.OtherMetadata[manifest.InferredAccessibilityMetadataKey].(map[string]any)
	if !ok {
		inferred = make(map[string]any)
		if metadata.OtherMetadata == nil {
			metadata.OtherMetadata = make(map[string]any)
		}
		metadata.OtherMetadata[manifest.InferredAccessibilityMetadataKey] = inferred
	}
	inferred[key] = value
}

// jsonStrings returns a list of strings in the form decoded JSON takes.
func jsonStrings[T ~string](values []T) []any {
	list := make([]any, len(values))
	for i, value := range values {
		list[i] = string(value)
	}
	return list
}
