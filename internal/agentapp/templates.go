package agentapp

import (
	"errors"
	"slices"
)

// Template is a versioned, dependency-free starting point. It names only
// capabilities already enforced by Steward; it never contains credentials,
// upstream origins, private keys, or mutable image tags.
type Template struct {
	ID          string    `json:"id"`
	Summary     string    `json:"summary"`
	ToolProfile string    `json:"tool_profile"`
	Skills      []string  `json:"skills"`
	Connectors  []string  `json:"connector_ids"`
	Events      bool      `json:"controller_events"`
	Resources   Resources `json:"resources"`
}

var builtinTemplates = []Template{
	{
		ID: "workspace", Summary: "General Hermes workspace with durable state and no optional network capability.",
		ToolProfile: "workspace", Skills: []string{"workspace-audit"},
		Connectors: []string{}, Resources: Resources{
			CPUMillis: 1000, MemoryMiB: 1024, DiskMiB: 2048, PIDs: 256,
		},
	},
	{
		ID: "research", Summary: "Source-grounded web research through policy-bound search, read, and extraction connectors.",
		ToolProfile: "research", Skills: []string{"steward-research"},
		Connectors: []string{
			"steward-browser-read", "steward-browser-search",
			"steward-research-extract", "steward-research-search",
		},
		Events: true, Resources: Resources{
			CPUMillis: 2000, MemoryMiB: 4096, DiskMiB: 8192, PIDs: 512,
		},
	},
	{
		ID: "developer", Summary: "Hermes coding worker using the policy-bound Codex connector.",
		ToolProfile: "developer", Skills: []string{"steward-coding-worker"},
		Connectors: []string{"steward-codex"}, Resources: Resources{
			CPUMillis: 4000, MemoryMiB: 8192, DiskMiB: 16384, PIDs: 1024,
		},
	},
}

func BuiltinTemplates() []Template {
	result := make([]Template, len(builtinTemplates))
	for index, template := range builtinTemplates {
		result[index] = cloneTemplate(template)
	}
	return result
}

func GetTemplate(id string) (Template, error) {
	for _, template := range builtinTemplates {
		if template.ID == id {
			return cloneTemplate(template), nil
		}
	}
	return Template{}, errors.New("agent template must be workspace, research, or developer")
}

func DefinitionFromTemplate(id, name, image string) (Definition, error) {
	template, err := GetTemplate(id)
	if err != nil {
		return Definition{}, err
	}
	definition := Definition{
		Schema: DefinitionSchema, Name: name, ToolProfile: template.ToolProfile,
		Runtime: Runtime{
			Engine: "hermes", Image: image, AdapterContract: "steward.hermes-agent.v1",
		},
		Model:  Model{Route: "local/default"},
		Skills: append([]string(nil), template.Skills...),
		Capabilities: CapabilityRequests{
			ConnectorIDs:     append([]string(nil), template.Connectors...),
			ControllerEvents: template.Events,
		},
		Resources: template.Resources,
		Placement: Placement{
			Architectures: []string{"amd64"}, Isolation: "hardened",
		},
		State: State{Persistent: true}, Lifetime: Lifetime{Mode: "service"},
	}
	if err := definition.Validate(); err != nil {
		return Definition{}, err
	}
	return definition, nil
}

func cloneTemplate(template Template) Template {
	template.Skills = slices.Clone(template.Skills)
	template.Connectors = slices.Clone(template.Connectors)
	return template
}
