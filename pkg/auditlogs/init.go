package auditlogs

import (
	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"encoding/json"
)


func (auditlogsPlugin *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}


// initialize state
func (auditlogsPlugin *Plugin) Init(cfg string) error {
	// auditlogsPlugin.Config.Reset() // I want to read configuration from falco.yaml not direct from the source code
	auditlogsPlugin.Config.auditLogsFilePath = "/home/sherlock/Desktop/falcoplugin/gcp_audits.json"
	err := json.Unmarshal([]byte(cfg), &auditlogsPlugin.Config)

	if err != nil {
		return err
	}
	return nil
}