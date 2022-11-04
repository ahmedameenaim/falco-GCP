package auditlogs

import (
	"context"
	"fmt"
	"io/ioutil"

	"cloud.google.com/go/pubsub"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

func (auditlogsPlugin *Plugin) pullMsgsSync(ctx context.Context, projectID, subID string) (chan []byte, chan error) {
	project_id := projectID
	sub_id := subID

	client, err := pubsub.NewClient(ctx, project_id)

	if err != nil {
		fmt.Printf("pubsub.NewClient: %v", err)
	}

	sub := client.Subscription(sub_id)

	sub.ReceiveSettings.Synchronous = true
	sub.ReceiveSettings.MaxOutstandingMessages = 10

	eventC := make(chan []byte)
	errC := make(chan error)

	go func() {

		defer close(eventC)
		defer close(errC)

		for {

			err = sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {
				eventC <- msg.Data
				msg.Ack()
			})

			if err != nil {
				errC <- err
				fmt.Printf("error is : %v", err)
				return
			}

		}

	}()

	return eventC, errC

}

func (auditlogsPlugin *Plugin) String(evt sdk.EventReader) (string, error) {

	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	return fmt.Sprintf("%v", evtStr), nil
}
