package auditlogs

import (
	"fmt"
	"io/ioutil"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

func (auditlogsPlugin *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "al.principal.email", Desc: "GCP principal email who committed the action"},
		{Type: "string", Name: "al.principal.ip", Desc: "GCP principal caller IP"},
		{Type: "string", Name: "al.principal.useragent", Desc: "GCP principal caller useragent"},
		{Type: "string", Name: "al.principal.authorinfo", Desc: "GCP authorization information affected resource"},
		{Type: "string", Name: "al.service.name", Desc: "GCP API service name"},
		{Type: "string", Name: "al.service.policyDelta", Desc: "GCP service resource access policy"},
		{Type: "string", Name: "al.service.request", Desc: "GCP API raw request"},
		{Type: "string", Name: "al.method.name", Desc: "GCP API service  method executed"},
	}
}

func (auditlogsPlugin *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {

	if evt.EventNum() != auditlogsPlugin.lastEventNum {
		
		evtBytes, err := ioutil.ReadAll(evt.Reader())
		if err != nil {
			return err
		}
		// For this plugin, events are always strings
		evtString := string(evtBytes)

		auditlogsPlugin.jdata, err = auditlogsPlugin.jparser.Parse(evtString)
		if err != nil {
			// Not a json file, so not present.
			return err
		}
		auditlogsPlugin.jdataEvtnum = evt.EventNum()

	}


	switch req.Field() {

	case "al.principal.email":
		principalEmail := string(auditlogsPlugin.jdata.Get("protoPayload").Get("authenticationInfo").Get("principalEmail").GetStringBytes())
		req.SetValue(principalEmail)

	case "al.principal.ip":
		principalIP := string(auditlogsPlugin.jdata.Get("protoPayload").Get("requestMetadata").Get("callerIp").GetStringBytes())
		req.SetValue(principalIP)

	case "al.principal.useragent":
		principalUserAgent := auditlogsPlugin.jdata.Get("protoPayload").Get("requestMetadata").Get("callerSuppliedUserAgent")
		if principalUserAgent != nil {
			req.SetValue(string(principalUserAgent.GetStringBytes()))
		} else {
			fmt.Println("Principal User Agent was omitted!")
		}

	case "al.principal.authorinfo":
		principalAuthorizationInfo := auditlogsPlugin.jdata.Get("protoPayload").Get("authorizationInfo").String()
		req.SetValue(principalAuthorizationInfo)

	case "al.service.name":
		serviceName := string(auditlogsPlugin.jdata.Get("protoPayload").Get("serviceName").GetStringBytes())
		req.SetValue(serviceName)

	case "al.service.request":
		request := auditlogsPlugin.jdata.Get("protoPayload").Get("request").String()
		req.SetValue(request)

	case "al.service.policyDelta":
		resource := string(auditlogsPlugin.jdata.Get("resource").Get("type").GetStringBytes())
		if resource == "gcs_bucket" {
			bindingDeltas := auditlogsPlugin.jdata.Get("protoPayload").Get("serviceData").Get("policyDelta").Get("bindingDeltas").String()
			req.SetValue(bindingDeltas)
		} else {
			bindingDeltas := auditlogsPlugin.jdata.Get("protoPayload").Get("metadata").Get("datasetChange").Get("bindingDeltas").String()
			req.SetValue(bindingDeltas)
		}

	case "al.method.name":
		serviceName := string(auditlogsPlugin.jdata.Get("protoPayload").Get("methodName").GetStringBytes())
		req.SetValue(serviceName)

	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}
	return nil
}