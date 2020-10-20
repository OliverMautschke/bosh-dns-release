package monitoring

import (
	"context"
	"errors"
	"sort"
	"fmt"
	"time"
	"os"
	"sync"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// DNSRequestType defines which type of dns request is handled
type DNSRequestType string
type key int

const(
	// DNSRequestTypeInternal is used for internal dns requests
	DNSRequestTypeInternal DNSRequestType = "internal"
	// DNSRequestTypeExternal is used for external dns requests
	DNSRequestTypeExternal DNSRequestType = "external"

	dnsRequestContext key = iota
)

func invertMap(m map[string]int) (map[int][]string, []int) {
	var newKeys []int
	invMap := make(map[int][]string)
	for key, val := range m {
		found := false
		for _, i := range newKeys {
			if i == val {
				found = true
			}
		}
		if !found {
			newKeys = append(newKeys, val)
		}
		invMap[val] = append(invMap[val], key)
	}
	return invMap, newKeys
}

// NewRequestContext Creates a new context for the given request typeß
func NewRequestContext(t DNSRequestType) context.Context {
	return context.WithValue(context.Background(), dnsRequestContext, t)
}

// NewPluginHandlerAdapter creates a new PluginHandler for both internal and external dns requests
func NewPluginHandlerAdapter(internalHandler dns.Handler, externalHandler dns.Handler, requestManager RequestCounter) pluginHandlerAdapter {
	pa := pluginHandlerAdapter{internalHandler: internalHandler, externalHandler: externalHandler, requestManager: requestManager}
	pa.intRequests = make(map[string]int)
	pa.extRequests = make(map[string]int)
	return pa
}

type pluginHandlerAdapter struct {
	internalHandler dns.Handler
	externalHandler dns.Handler
	requestManager RequestCounter
	intRequests map[string]int
	extRequests map[string]int
	lock sync.RWMutex
}

func(p pluginHandlerAdapter) Name() string {
	return "pluginHandlerAdapter"
}

//go:generate counterfeiter . RequestCounter

type RequestCounter interface {
	IncrementExternalCounter()
	IncrementInternalCounter()
}

type RequestManager struct {
	externalRequestsCounter prometheus.Counter
	internalRequestsCounter prometheus.Counter
}

func NewRequestManager() RequestManager {
	extReqs := promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "boshdns",
		Subsystem: "requests",
		Name:      "external_total",
		Help:      "The count of external requests.",
	})
	intReqs := promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "boshdns",
		Subsystem: "requests",
		Name:      "internal_total",
		Help:      "The count of internal requests.",
	})
	return RequestManager{externalRequestsCounter: extReqs, internalRequestsCounter: intReqs}
}

func(m RequestManager) IncrementExternalCounter() {
	m.externalRequestsCounter.Inc()
}

func(m RequestManager) IncrementInternalCounter() {
	m.internalRequestsCounter.Inc()
}

func(p pluginHandlerAdapter) ServeDNS(ctx context.Context, writer dns.ResponseWriter, m *dns.Msg) (int, error) {
	v := ctx.Value(dnsRequestContext)

	if v == nil {
		return 0, errors.New("No DNS request type found in context")
	}

	if p.externalHandler != nil && v == DNSRequestTypeExternal {
		for _, q := range m.Question {
			p.lock.RLock()
			p.extRequests[q.Name]++
			p.lock.RUnlock()
		}
		p.externalHandler.ServeDNS(writer, m)
		p.requestManager.IncrementExternalCounter()
	} else if p.internalHandler != nil && v == DNSRequestTypeInternal {
		for _, q := range m.Question {
			p.lock.RLock()
			p.intRequests[q.Name]++
			p.lock.RUnlock()
		}
		p.internalHandler.ServeDNS(writer, m)
		p.requestManager.IncrementInternalCounter()
	}

	t := time.Now()

	p.lock.RLock()

	fileNameInt := "/tmp/boshdns_top_internal_requests_" + t.Format("2006-01-02-15") + ".txt"
	if _, err := os.Stat(fileNameInt); os.IsNotExist(err) {
		intInvMap, intKeys := invertMap(p.intRequests)
		extInvMap, extKeys := invertMap(p.extRequests)

		sort.Sort(sort.Reverse(sort.IntSlice(intKeys)))
		sort.Sort(sort.Reverse(sort.IntSlice(extKeys)))

		internalData := ""
		externalData := ""

		for ind, ik := range intKeys {
			if ind > 100 {
				break
			}
			internalData += fmt.Sprintf("Count: %d Name(s): %s.\n", ik, intInvMap[ik])
		}

		for ind, ek := range extKeys {
			if ind > 100 {
				break
			}
			externalData += fmt.Sprintf("Count: %d Name(s): %s.\n", ek, extInvMap[ek])
		}

		intFile, _ := os.Create(fileNameInt)
		defer intFile.Close()
		intFile.WriteString(internalData)

		fileNameExt := "/tmp/boshdns_top_external_requests_" + t.Format("2006-01-02-15") + ".txt"

		extFile, _ := os.Create(fileNameExt)
		defer extFile.Close()
		extFile.WriteString(externalData)

		p.intRequests = make(map[string]int)
		p.extRequests = make(map[string]int)
	}
	p.lock.RUnlock()

	return 0, nil
}
