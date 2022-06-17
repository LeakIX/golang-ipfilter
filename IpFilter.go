package filter

import (
	"bufio"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

type IpFilter struct {
	refreshUrl      string
	refreshInterval time.Duration
	filterLock      sync.RWMutex
	denyList        []*net.IPNet
	HttpErrorChan   chan error
}

type Option func(filter *IpFilter) error

func NewIpFilter(opts ...Option) (*IpFilter, error) {
	filter := &IpFilter{
		HttpErrorChan: make(chan error),
	}
	for _, opt := range opts {
		err := opt(filter)
		if err != nil {
			return nil, err
		}
	}
	return filter, nil
}

func WithRanges(ranges ...string) Option {
	return func(filter *IpFilter) error {
		return filter.AddRanges(ranges...)
	}
}

func WithHttpRefresh(refreshUrl string, refreshInterval time.Duration) Option {
	return func(filter *IpFilter) error {
		filter.refreshUrl = refreshUrl
		filter.refreshInterval = refreshInterval
		go filter.startUpdatesRanges()
		return nil
	}
}

func (filter *IpFilter) AddRanges(ranges ...string) (err error) {
	for _, ipRange := range ranges {
		err = filter.AddRange(ipRange)
		if err != nil {
			return err
		}
	}
	return nil
}

func (filter *IpFilter) AddRange(ipRange string) (err error) {
	_, parsedRange, err := net.ParseCIDR(ipRange)
	if err != nil {
		return err
	}
	if parsedRange.String() != ipRange {
		return errors.New("requested range is not valid " + ipRange + " vs " + parsedRange.String())
	}
	if filter.IsRangeInDenyList(ipRange) {
		return nil
	}
	log.Printf("adding %s in blocklist", ipRange)
	filter.filterLock.Lock()
	defer filter.filterLock.Unlock()
	filter.denyList = append(filter.denyList, parsedRange)
	return nil
}

func (filter *IpFilter) IsNetIpAllowed(ip net.IP) bool {
	filter.filterLock.RLock()
	defer filter.filterLock.RUnlock()
	for _, block := range filter.denyList {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

func (filter *IpFilter) IsRangeInDenyList(ipRange string) bool {
	filter.filterLock.RLock()
	defer filter.filterLock.RUnlock()
	for _, block := range filter.denyList {
		if block.String() == ipRange {
			return true
		}
	}
	return false
}

func (filter *IpFilter) IsIpAllowed(ipString string) bool {
	ip := net.ParseIP(ipString)
	if ip == nil {
		return false
	}
	filter.filterLock.RLock()
	defer filter.filterLock.RUnlock()
	for _, block := range filter.denyList {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

var ErrHttpRefreshNetwork = errors.New("network error refreshing blocklist from http source")
var ErrHttpRefreshStatus = errors.New("bad http status from http blocklist source")

func (filter *IpFilter) startUpdatesRanges() {
	for {
		err := filter.updateRanges()
		if err != nil {
			select {
			case filter.HttpErrorChan <- err:
			default:
				log.Println(err)
			}
		}
		time.Sleep(filter.refreshInterval)
	}
}

func (filter *IpFilter) updateRanges() error {
	resp, err := http.Get(filter.refreshUrl)
	if err != nil {
		return ErrHttpRefreshNetwork
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ErrHttpRefreshStatus
	}
	reader := bufio.NewScanner(resp.Body)
	for reader.Scan() {
		err = filter.AddRange(reader.Text())
		if err != nil {
			select {
			case filter.HttpErrorChan <- err:
			default:
				log.Println(err)
			}
		}
	}
	return nil
}

var PrivateRanges = []string{
	"::1/128",
	"fe80::/10",
	"fc00::/7",
	// Local network
	"127.0.0.0/8",
	// Current network
	"0.0.0.0/8",
	// Private
	"192.168.0.0/16",
	"10.0.0.0/8",
	"172.16.0.0/12",
	// CGN
	"100.64.0.0/10",
	// Multicast
	"224.0.0.0/4",
	// Reserved
	"255.255.255.255/32",
	"240.0.0.0/4",
}
