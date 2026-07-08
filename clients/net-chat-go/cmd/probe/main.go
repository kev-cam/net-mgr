package main

import (
	"fmt"
	"log"
	"time"

	"github.com/kev-cam/net-chat-go/internal/netmgr"
)

func main() {
	c, err := netmgr.Dial("127.0.0.1:7531", 5*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	c.SetAs("dkc@bigsony")
	if err := c.Hello("dkc@bigsony"); err != nil {
		log.Fatal(err)
	}
	// Loopback: skip AUTH (net-mgr trusts loopback callers).
	rows, err := c.Snapshot("bitchat_peers", "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("bitchat_peers rows: %d\n", len(rows))
	for _, r := range rows {
		fmt.Printf("  %s  %s  connected=%s  last_seen=%s\n",
			r["peer_id"], r["nickname"], r["is_connected"], r["last_seen"])
	}
}
