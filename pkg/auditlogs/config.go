package auditlogs

import "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"

type Plugin struct {
	plugins.BasePlugin
	Config PluginConfig

	lastLogEvent 	 LogEvent
	lastEventNum     uint64
}

type PluginConfig struct {
	AuditLogsFilePath string `json:"path" jsonschema:"title=path"`
	SubscriptionID    string `json:"sub_id" jsonschema:"title=sub_id"`
	ProjectID         string `json:"project_id" jsonschema:"title=project_id"`
}

func (auditlogsPlugin *PluginConfig) Reset() {

}
