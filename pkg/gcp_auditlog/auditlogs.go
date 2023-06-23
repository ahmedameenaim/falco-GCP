package gcp_auditlog

import (

	// "io/ioutil"
	// "fmt"
	// "github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"context"
	"encoding/json"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	PluginID          uint32 = 999
	PluginName               = "gcp_auditlog"
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

		ServiceName  string          `json:"serviceName"`
		MethodName   string          `json:"methodName"`
		Request      json.RawMessage `json:"request,omitempty"`
		TimeStamp    uint64          `json:"timestamp"`
		ResourceName string          `json:"resourceName"`
		//This field would be deprecated, metadata field will be the alternative
		ServiceData struct {
			PolicyDelta struct {
				BindingDeltas []struct {
					Action string `json:"action"`
					Role   string `json:"role"`
					Member string `json:"member"`
				} `json:"bindingDeltas"`
			} `json:"policyDelta"`
		} `json:"serviceData,omitempty"`
		MetaData struct {
			DatasetChange struct {
				BindingDeltas []struct {
					Action string `json:"action"`
					Role   string `json:"role"`
					Member string `json:"member"`
				} `json:"bindingDeltas"`
			} `json:"datasetChange"`
		} `json:"metadata,omitempty"`
		ResourceLocation struct {
			CurrentLocations []string `json:"currentLocations"`
		} `json:"resourceLocation"`
	} `json:"protoPayload"`

	Resource struct {
		Type   string            `json:"type"`
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

func (p *Plugin) Open(topic string) (source.Instance, error) {

	ctx, cancel := context.WithCancel(context.Background())

	eventsC, errC := p.pullMsgsSync(ctx, p.Config.ProjectID, p.Config.SubscriptionID)
	pushEventC := make(chan source.PushEvent)

	go func() {
		defer close(eventsC)
		for {
			select {
			case messages := <-eventsC:
				pushEventC <- source.PushEvent{Data: messages}

			case e := <-errC:
				pushEventC <- source.PushEvent{Err: e}
				return
			}
		}
	}()

	return source.NewPushInstance(pushEventC, source.WithInstanceClose(cancel))

}

// func (p *Plugin) Open(topic string) (source.Instance, error) {

// 	pull := func(ctx context.Context, evt sdk.EventWriter) error {

// 		contents, err := ioutil.ReadFile(p.Config.AuditLogsFilePath)

// 		if err != nil {
// 			fmt.Errorf("Error when opening file: ", err)
// 		}

// 		// Write the event data
// 		n, err := evt.Writer().Write(contents)

// 		if err != nil {
// 			return err
// 		} else if n < len(contents) {
// 			return fmt.Errorf("auditlogs message too long: %d, but %d were written", len(contents), n)
// 		}

// 		return err
// 	}
// 	return source.NewPullInstance(pull)
// }
