package auditlogs

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

func (auditlogsPlugin *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "al.principal", Desc: "GCP principal email who committed the action"},
		{Type: "string", Name: "al.callerip", Desc: "GCP principal caller IP"},
		{Type: "string", Name: "al.useragent", Desc: "GCP principal caller useragent"},
		{Type: "string", Name: "al.service.name", Desc: "GCP API service name"},
		{Type: "string", Name: "al.method.name", Desc: "GCP API service  method executed"},
		{Type: "string", Name: "al.authorization.resources", Desc: "GCP authorization information affected resource", IsList: true, Arg: sdk.FieldEntryArg{
			IsRequired: false,
			IsIndex:    true,
		},
		},
		{Type: "string", Name: "al.authorization.permissions", Desc: "GCP authorization information granted permission", IsList: true, Arg: sdk.FieldEntryArg{
			IsRequired: false,
			IsIndex:    true,
		},
		},

		{Type: "string", Name: "al.resource.locations", Desc: "GCP resource locations zone", IsList: true, Arg: sdk.FieldEntryArg{
			IsRequired: false,
			IsIndex:    true,
		},
		},

		{Type: "string", Name: "al.meta", Desc: "GCP resource metadata"},
		{Type: "string", Name: "al.resource.type", Desc: "GCP API service type"},

		{Type: "string", Name: "al.bind.actions", Desc: "GCP API service type", IsList: true, Arg: sdk.FieldEntryArg{
			IsRequired: false,
			IsIndex:    true,
		},
		},

		{Type: "string", Name: "al.bind.members", Desc: "GCP API service type", IsList: true, Arg: sdk.FieldEntryArg{
			IsRequired: false,
			IsIndex:    true,
		},
		},
	}
}

func (auditlogsPlugin *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {

	data := auditlogsPlugin.lastLogEvent


	if evt.EventNum() != auditlogsPlugin.lastEventNum {


		evtBytes, err := ioutil.ReadAll(evt.Reader())
		if err != nil {
			return err
		}
	
		err = json.Unmarshal(evtBytes, &data)
		if err != nil {
			return err
		}
	
		auditlogsPlugin.lastLogEvent = data
		auditlogsPlugin.lastEventNum = evt.EventNum()

	}

	switch req.Field() {

	case "al.principal":
		req.SetValue(data.ProtoPayload.AuthenticationInfo.PrincipalEmail)
	case "al.callerip":
		req.SetValue(data.ProtoPayload.RequestMetadata.CallerIp)
	case "al.useragent":
		req.SetValue(data.ProtoPayload.RequestMetadata.UserAgent)
	case "al.service.name":
		req.SetValue(data.ProtoPayload.ServiceName)
	case "al.method.name":
		req.SetValue(data.ProtoPayload.MethodName)
	case "al.authorization.resources":
		resources := []string{}
		for _, i := range data.ProtoPayload.AuthorizationInfo {
			resources = append(resources, i.Resource)
		}
		req.SetValue(resources)
	case "al.authorization.permissions":
		permissions := []string{}
		for _, i := range data.ProtoPayload.AuthorizationInfo {
			permissions = append(permissions, i.Permission)
		}
		req.SetValue(permissions)
	case "al.resource.locations":
		locations := []string{}

		locations = append(locations, data.ProtoPayload.ResourceLocation.CurrentLocations...)
		req.SetValue(locations)
	case "al.meta":
		var meta string
		for key, value := range data.Resource.Labels {
			meta += key + ":" + value + " "
		}
		req.SetValue(meta)
	case "al.resource.type":
		req.SetValue(data.Resource.Type)
	case "al.bind.actions":
		var actions []string
		bindingData := data.ProtoPayload.ServiceData.PolicyDelta.BindingDeltas
		for index := range bindingData {
			actions = append(actions, bindingData[index].Action)
		}
		req.SetValue(actions)
	case "al.bind.members":
		var members []string
		bindingData := data.ProtoPayload.ServiceData.PolicyDelta.BindingDeltas
		for index := range bindingData {
			members = append(members, bindingData[index].Member)
		}
		req.SetValue(members)
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}