package auditlogs

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
    "fmt"
	"io/ioutil"
	"context"
	"log"
)


func (p *Plugin) Open(params string) (source.Instance, error) {

	pull := func(ctx context.Context, evt sdk.EventWriter) error {

		contents, err := ioutil.ReadFile(p.Config.auditLogsFilePath)

		if err != nil {
			log.Fatal("Error when opening file: ", err)
		}

		// Write the event data
		n, err := evt.Writer().Write(contents)

		if err != nil {
			return err
		} else if n < len(contents) {
			return fmt.Errorf("auditlogs message too long: %d, but %d were written", len(contents), n)
		}
		
		return err
	}

	return source.NewPullInstance(pull)

}