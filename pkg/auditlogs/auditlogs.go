/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auditlogs

import ( 
	"encoding/json" 
    "fmt"
	"io/ioutil"
	"log"
	"context"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	PluginID          uint32 = 999
	PluginName               = "auditlogs"
	PluginDescription        = "Reference plugin for educational purposes"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.5.0"
	PluginEventSource        = "auditlogs"
)


// The data struct for the decoded data
// Notice that all fields must be exportable!
type LogEvent struct {
    ProtoPayload struct {
        AuthenticationInfo struct {
            PrincipalEmail string `json:"principalEmail"`
        } `json:"authenticationInfo"`

        RequestMetadata struct {
            CallerIp string `json: "callerIp"`
        } `json: "requestMetadata"`

        ServiceName string `json: "serviceName"`
        MethodName string `json: "methodName"`
    
    
    } `json: "protoPayload"`

}


type PluginConfig struct {
	// This reflects potential internal state for the plugin. In
	auditLogsFilePath string `json:"path" jsonschema:"title=Sample jitter,description=A random amount added"`
}

type Plugin struct {
	plugins.BasePlugin

	lastLogEvent LogEvent

	// Contains the init configuration values
	config PluginConfig
}

func (p *PluginConfig) setDefault() {
}

func (auditlogsPlugin *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          PluginID,
		Name:        PluginName,
		Description: PluginDescription,
		Contact:     PluginContact,
		Version:     PluginVersion,
		EventSource: PluginEventSource,
	}
}


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

func (auditlogsPlugin *Plugin) Init(cfg string) error {
	// initialize state
	auditlogsPlugin.config.auditLogsFilePath = "/**/falcoplugin/gcp_audits.json"

	err := json.Unmarshal([]byte(cfg), &auditlogsPlugin)

	if err != nil {
		return err
	}

	return nil
}

func (auditlogsPlugin *Plugin) Destroy() {
	// nothing to do here
}


func (p *Plugin) Open(prms string) (source.Instance, error) {

	pull := func(ctx context.Context, evt sdk.EventWriter) error {

		contents, err := ioutil.ReadFile(p.config.auditLogsFilePath)
		if err != nil {
			log.Fatal("Error when opening file: ", err)
		}
	
		// Now let's unmarshall the data into `payload`
		var payload LogEvent
		err = json.Unmarshal(contents, &payload)
	
		if err != nil {
			log.Fatal("Error during Unmarshal(): ", err)
		}

		evt.SetTimestamp(uint64(time.Now().UnixNano()))
		
		fmt.Printf("email: %s\n", payload.ProtoPayload.AuthenticationInfo.PrincipalEmail)
		fmt.Printf("IP: %s\n", payload.ProtoPayload.RequestMetadata.CallerIp)
		fmt.Printf("Method: %s\n", payload.ProtoPayload.MethodName)
		
		return err

	}


	return source.NewPullInstance(pull)
}

func (m *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{
			Type: "string",
			Name: "auditlogs.principal",
			Desc: "GCP principal email who committed the action",
			// Arg:  sdk.FieldEntryArg{IsRequired: true, IsKey: true},

		},
		{
			Type: "uint64",
			Name: "dummy.value",
			Desc: "The sample value in the event",
		},
		{
			Type: "string",
			Name: "dummy.strvalue",
			Desc: "The sample value in the event, as a string",
		},
	}
}


func (auditlogsPlugin *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	
	data := auditlogsPlugin.lastLogEvent

	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return err
	}

	err = json.Unmarshal(evtBytes, &data)
	if err != nil {
		return err
	}

	auditlogsPlugin.lastLogEvent = data

	fmt.Printf("%+v\n", data)


	switch req.Field() {

	case "auditlogs.principal":
		req.SetValue(data.ProtoPayload.AuthenticationInfo.PrincipalEmail) 
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}


// todo: optimize this to cache by event number
func (auditlogsPlugin *Plugin) String(evt sdk.EventReader) (string, error) {

	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	fmt.Printf(evtStr)


	// The string representation of an event is a json object with the sample
	return fmt.Sprintf("{\"sample\": \"%s\"}", evtStr), nil
}


