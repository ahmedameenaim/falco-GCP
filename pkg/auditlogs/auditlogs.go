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

	"io/ioutil"
	"fmt"
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
type LogEvent struct {
    ProtoPayload struct {
        AuthenticationInfo struct {
            PrincipalEmail string `json:"principalEmail"`
        } `json:"authenticationInfo"`

        RequestMetadata struct {
            CallerIp  string `json:"callerIp"`
            UserAgent string `json:"callerSuppliedUserAgent"`
        } `json:"requestMetadata"`

		AuthorizationInfo []struct {
            Resource   string `json:"resource"`
            Permission string `json:"permission"`

        } `json:"authorizationInfo"`

        ServiceName  string `json:"serviceName"`
        MethodName   string `json:"methodName"`
		TimeStamp    uint64 `json:"timestamp"`
        ResourceName string `json:"resourceName"`
		ResourceLocation struct {
			CurrentLocations []string `json:"currentLocations"`
		} `json:resourceLocation`
		
	
	} `json:"protoPayload"`

	Resource struct {
        Type   string `json:"type"`
        Labels map[string]string `json:"labels"`
    } `json:"resource"`

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

func (auditlogsPlugin *Plugin) String(evt sdk.EventReader) (string, error) {

	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	return fmt.Sprintf("%v", evtStr), nil
}


