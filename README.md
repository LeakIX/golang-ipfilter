# Golang IpFilter

This library is made for testing individual IPs against a blocklist.

An HTTP source can be provided for regular updates of the blocklist.

## Basic usage

```golang
package main

import (
	"github.com/LeakIX/golang-ipfilter"
	"log"
	"time"
)

func main() {
	// Create a new filter, including private ranges, updating its blocklist from remote every 60 seconds :
	ipFilter, err := filter.NewIpFilter(
		filter.WithRanges(filter.PrivateRanges...), 
		filter.WithHttpRefresh("https://some.website/blocked-networks.txt", 60*time.Second))
	if err != nil {
		log.Fatalln(err)
	}
	// Add a range to the filter
	err = ipFilter.AddRange("192.168.1.0/24")
	if err != nil {
		log.Fatalln(err)
    }
	// Handle HTTP refresh errors
	go func() {
		for {
			err := <- ipFilter.HttpErrorChan
			log.Println(err)
        }
    }()
	if ipFilter.IsIpAllowed("127.0.0.1") {
		// 127.0.0.1 is allowed
    } else {
		// 127.0.0.1 is not allowed
    }
}
```
