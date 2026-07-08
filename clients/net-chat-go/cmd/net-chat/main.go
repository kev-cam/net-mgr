// net-chat — Go port of the Perl net-chat client.
//
// STATUS: connects, authenticates, subscribes to one chat session, and
// dumps every ROW frame it receives to stdout. Enough to validate the
// wire codec + AUTH handshake against the real nas3 daemon.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kev-cam/net-chat-go/internal/netmgr"
	"github.com/kev-cam/net-chat-go/internal/ui"
)

func main() {
	listen := flag.String("listen", "nas3:7531",
		"host:port of the net-mgr daemon (matches Perl net-chat --listen)")
	session := flag.String("session", "General",
		"chat session name to SUBSCRIBE against")
	keyID := flag.String("key-id", "",
		"identity for AUTH (default $USER@$hostname)")
	keyFile := flag.String("key-file", "",
		"private key file for AUTH (default ~/.ssh/id_ed25519 | id_rsa | id_ecdsa)")
	as := flag.String("as", "",
		"consumer/sender name carried on HELLO (default = key-id)")
	dialTimeout := flag.Duration("dial-timeout", 5*time.Second,
		"timeout for the initial TCP connect")
	doAuth := flag.Bool("auth", false,
		"AUTH at startup (ssh-keygen -Y sign). Off by default — the daemon "+
			"trusts the `as` field on loopback, and public sessions accept "+
			"anonymous SUBSCRIBE/POST anywhere. Turn on only for closed "+
			"sessions on remote daemons.")
	// Legacy compat: --no-auth used to be the opt-in-to-skip flag.
	// Accepting it (as a no-op) keeps existing invocations working.
	_ = flag.Bool("no-auth", false, "(deprecated, no-op — AUTH is now off by default)")
	post := flag.String("post", "",
		"send this text as one message to --session and exit (skips subscribe)")
	gui := flag.Bool("gui", false,
		"launch the Fyne desktop UI instead of the streaming CLI")
	flag.Parse()

	if *keyID == "" {
		*keyID = netmgr.DefaultKeyID()
	}
	if *keyFile == "" {
		p, err := netmgr.DefaultKeyFile()
		if err != nil && *doAuth {
			log.Fatalf("net-chat: %v (pass --key-file or drop --auth)", err)
		}
		*keyFile = p
	}
	if *as == "" {
		*as = *keyID
	}

	if err := run(*listen, *session, *keyID, *keyFile, *as, *post, *dialTimeout, *doAuth, *gui); err != nil {
		log.Fatalf("net-chat: %v", err)
	}
}

func run(addr, session, keyID, keyFile, as, post string, dialTimeout time.Duration, doAuth, gui bool) error {
	c, err := netmgr.Dial(addr, dialTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetAs(as)

	if err := c.Hello(as); err != nil {
		return fmt.Errorf("HELLO: %w", err)
	}
	fmt.Fprintf(os.Stderr, "hello sent (consumer=%s)\n", as)

	if doAuth {
		if err := c.Auth(keyID, keyFile); err != nil {
			return fmt.Errorf("AUTH: %w", err)
		}
		fmt.Fprintf(os.Stderr, "auth ok (key_id=%s)\n", keyID)
	}

	if post != "" {
		reply, err := c.Post(session, post)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "posted to %q (reply=%v)\n", session, reply)
		return nil
	}

	if gui {
		// Ctrl connection is dialed LAZILY on first Post/CHAT_* —
		// deferring the second ssh-keygen sign avoids a launch-
		// time hang when the key needs a passphrase or ssh-agent.
		// Two-connection model still matches Perl bin/net-chat's
		// (stream + ctrl) pattern; just delayed.
		ctrlDial := func() (*netmgr.Client, error) {
			ctrl, err := netmgr.Dial(addr, dialTimeout)
			if err != nil {
				return nil, fmt.Errorf("dial ctrl: %w", err)
			}
			ctrl.SetAs(as)
			if err := ctrl.Hello(as); err != nil {
				return nil, fmt.Errorf("ctrl HELLO: %w", err)
			}
			if doAuth {
				if err := ctrl.Auth(keyID, keyFile); err != nil {
					return nil, fmt.Errorf("ctrl AUTH: %w", err)
				}
			}
			return ctrl, nil
		}
		return ui.Run(ui.Config{Stream: c, CtrlDial: ctrlDial, Session: session})
	}

	sub, err := c.SubscribeChat(session)
	if err != nil {
		return fmt.Errorf("SUBSCRIBE: %w", err)
	}
	fmt.Fprintf(os.Stderr, "subscribed to chat_messages session=%q (sub=%s); streaming...\n",
		session, sub)

	// Ctrl-C interrupts the read loop cleanly.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		c.Close()
	}()

	for {
		cmd, raw, err := c.Recv()
		if err != nil {
			// A closed connection at EOF is the normal Ctrl-C path.
			if err.Error() == "EOF" || err.Error() == "use of closed network connection" {
				return nil
			}
			return err
		}
		if cmd == nil {
			continue
		}
		switch cmd.Verb {
		case "ROW":
			fmt.Printf("ROW  sub=%s table=%s op=%s body=%q sender=%s session=%s\n",
				cmd.KV["sub"], cmd.KV["table"], cmd.KV["op"],
				cmd.KV["body"], cmd.KV["sender"], cmd.KV["session"])
		case "EOS":
			fmt.Fprintf(os.Stderr, "EOS  sub=%s (initial snapshot done)\n", cmd.KV["sub"])
		default:
			fmt.Printf("%-8s %v\n", cmd.Verb, cmd.KV)
			_ = raw
		}
	}
}
