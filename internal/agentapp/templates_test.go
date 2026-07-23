package agentapp

import (
	"strings"
	"testing"
)

func TestBuiltinTemplatesProduceValidLeastAuthorityDefinitions(t *testing.T) {
	templates := BuiltinTemplates()
	if len(templates) != 3 ||
		templates[0].ID != "workspace" ||
		templates[1].ID != "research" ||
		templates[2].ID != "developer" {
		t.Fatalf("templates=%+v", templates)
	}
	image := "example.invalid/hermes@sha256:" + strings.Repeat("a", 64)
	for _, template := range templates {
		t.Run(template.ID, func(t *testing.T) {
			definition, err := DefinitionFromTemplate(template.ID, "agent-a", image)
			if err != nil || definition.Validate() != nil ||
				definition.ToolProfile != template.ToolProfile ||
				definition.Capabilities.ControllerEvents != template.Events {
				t.Fatalf("definition=%+v err=%v", definition, err)
			}
		})
	}
	templates[0].Skills[0] = "changed"
	again := BuiltinTemplates()
	if again[0].Skills[0] == "changed" {
		t.Fatal("template inventory returned mutable shared state")
	}
	if _, err := GetTemplate("unknown"); err == nil {
		t.Fatal("unknown template was accepted")
	}
}
