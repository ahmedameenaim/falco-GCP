package auditlogs

import "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"


type Plugin struct {
	plugins.BasePlugin
	Config 				PluginConfig


	lastLogEvent 		LogEvent
	
}


type PluginConfig struct {
	// auditLogsFilePath string
	auditLogsFilePath string  `json:"path" jsonschema:"title=path`

}

func (auditlogsPlugin *PluginConfig) Reset() {
	
}