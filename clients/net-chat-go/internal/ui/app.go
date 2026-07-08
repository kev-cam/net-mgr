// Package ui — Fyne desktop client for net-chat.
//
// Scope: session picker, message list, peer roster panel (right side),
// compose bar with Send. One connection, two live subscribes: the
// chat_messages sub cycles with the session picker; the bitchat_peers
// sub stays live across session switches so the roster stays fresh.
//
// One goroutine drains Recv() and routes ROWs by table. That keeps the
// bufio reader single-threaded (safe) and simplifies teardown.
//
// Next up:
//   - Per-sender palette for message log
//   - Fold/unfold for long messages
//   - Inline QR image for WIFI:...;; URIs
//   - File upload/download
package ui

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"image"
	"image/color"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/skip2/go-qrcode"

	"github.com/kev-cam/net-chat-go/internal/bitchat/mesh"
	"github.com/kev-cam/net-chat-go/internal/netmgr"
)

// meshSession is the pseudo-session name used to route the UI's
// message log to bitchat mesh AppEvents instead of net-mgr ROWs.
// Selecting it in the picker swaps the source; posting on it goes
// through mesh.Service.PostPublic / PostDM (@HEX:prefix routes DM).
const meshSession = "bitchat-mesh"

// wifiURIRe matches a WIFI:...;; URI anywhere in a message body. Same
// non-greedy shape bin/net-chat-autoresponder uses.
var wifiURIRe = regexp.MustCompile(`WIFI:.*?;;`)

// firstWifiURI returns the first WIFI: URI in body, or "" if none. The
// per-message QR renderer only renders one (multiple URIs in one
// message are rare enough that the second gets an unfold on the
// operator; we can promote to N images later if it comes up).
func firstWifiURI(body string) string {
	return wifiURIRe.FindString(body)
}

// renderQR returns a 160px QR image for uri, or nil on error. Medium
// ECC balances size vs. camera-scan reliability; matches the settings
// bin/net-chat's inline QR uses.
func renderQR(uri string) image.Image {
	if uri == "" {
		return nil
	}
	qr, err := qrcode.New(uri, qrcode.Medium)
	if err != nil {
		return nil
	}
	return qr.Image(160)
}

// senderPalette is a small set of muted, high-chroma colours picked to
// stay legible against both the light and dark Fyne themes. They tint
// a 4-pixel bar on the leading edge of each message; we don't tint
// the row background so theme-tuned text stays on a theme-controlled
// background and remains readable.
var senderPalette = []color.NRGBA{
	{0xE0, 0x4E, 0x4E, 0xFF}, // red
	{0xE0, 0x8A, 0x2E, 0xFF}, // orange
	{0xC7, 0xA6, 0x2A, 0xFF}, // amber
	{0x4E, 0xA5, 0x4E, 0xFF}, // green
	{0x35, 0xA5, 0x9C, 0xFF}, // teal
	{0x3E, 0x8A, 0xC7, 0xFF}, // blue
	{0x7A, 0x5C, 0xC7, 0xFF}, // indigo
	{0xB5, 0x4E, 0xA5, 0xFF}, // magenta
	{0x8A, 0x60, 0x3E, 0xFF}, // brown
	{0x6E, 0x7B, 0x8A, 0xFF}, // slate
}

// colorForSender maps a sender identity to a stable palette entry via
// a fnv32 hash. Same sender always gets the same colour across
// window sessions, but two different senders may hash to the same
// bucket — that's fine for a 10-slot palette.
func colorForSender(sender string) color.NRGBA {
	h := fnv.New32a()
	h.Write([]byte(sender))
	return senderPalette[h.Sum32()%uint32(len(senderPalette))]
}

const bridgeSession = "bitchat-bridge"

// Config is the wiring the caller (cmd/net-chat) hands us. The Stream
// connection is dialed LAZILY on a background goroutine inside Run()
// so the window opens even when the daemon is unreachable — Android
// launches with no network, phone off-WiFi, whatever. Otherwise
// main.go's synchronous Dial would keep the app on a blank screen
// forever. Connection status is surfaced in the status bar; a
// Connect… button opens a dialog for changing the address. CtrlDial
// (also called with an address) fires on the first Post/Upload/Files
// action, deferring its ssh-keygen sign.
type Config struct {
	StreamDial func(addr string) (*netmgr.Client, error)
	CtrlDial   func(addr string) (*netmgr.Client, error)
	Address    string // initial host:port; blank ⇒ don't auto-dial, show Connect dialog
	Session    string
	Title      string

	// Mesh is the optional native BitChat mesh service. When set,
	// the picker gains a "bitchat-mesh" session that drives from
	// its AppEvents, and its peer roster augments the net-mgr
	// bitchat_peers panel. When nil the UI behaves as before.
	Mesh *mesh.Service
}

// peer holds the roster row we display in the right-side panel.
type peer struct {
	peerID    string
	nickname  string
	connected bool
	lastSeen  string
}

// messageEntry is one line in the message log. Kept as a struct (not a
// pre-formatted string) so the list renderer can colour the leading
// bar per sender + toggle the fold state at bind time.
type messageEntry struct {
	sender string
	body   string
	folded bool // true = head + " [+]" only; false = full body
}

// foldable reports whether the body is long enough (>100 chars) or has
// embedded newlines — the only cases where folding actually hides
// something. Matches the Perl client's cut rule (first newline or
// col 100).
func (m messageEntry) foldable() bool {
	if strings.ContainsRune(m.body, '\n') {
		return true
	}
	return len(m.body) > 100
}

// displayBody returns the body text for the current fold state. When
// folded, cuts at the first newline or column 100 (whichever is
// earlier) and appends " [+]" as an affordance.
func (m messageEntry) displayBody() string {
	if !m.folded || !m.foldable() {
		return m.body
	}
	cut := len(m.body)
	if idx := strings.IndexByte(m.body, '\n'); idx >= 0 && idx < cut {
		cut = idx
	}
	if cut > 100 {
		cut = 100
	}
	return m.body[:cut] + " [+]"
}

// state carries the mutable UI wiring shared between the read loop and
// the session-switch handler. Guarded by mu so a user-driven switch
// doesn't race a mid-stream ROW.
type state struct {
	mu sync.Mutex

	session      string
	chatSubID    string
	peerSubID    string
	snapshotDone bool // true after the chat sub's initial snapshot EOS; live rows arrive unfolded

	msgs []messageEntry // message log; refresh msgList after mutating

	peers     map[string]*peer   // peer_id -> peer
	peerOrder []string           // stable display order (peer_id list)
	peerList  binding.StringList // display strings for the roster

	cancel context.CancelFunc // cancels the current readLoop

	// Lazy stream connection. Redialed when the operator hits
	// Connect… with a new address.
	address string
	stream  *netmgr.Client

	// Lazy control connection. Established on the first Post /
	// CHAT_* invocation, then reused for the window's lifetime.
	// Guarded by ctrlOnce so a concurrent Send + Upload don't race.
	ctrlOnce sync.Once
	ctrl     *netmgr.Client
	ctrlErr  error
}

// getCtrl returns the memoized ctrl connection, dialing on first use.
// Blocks until the ssh-keygen sign completes. Errors surface via the
// caller (typically shown in a dialog).
func (st *state) getCtrl(dial func(addr string) (*netmgr.Client, error)) (*netmgr.Client, error) {
	st.ctrlOnce.Do(func() {
		st.mu.Lock()
		addr := st.address
		st.mu.Unlock()
		if addr == "" {
			st.ctrlErr = errors.New("not connected — hit Connect… first")
			return
		}
		st.ctrl, st.ctrlErr = dial(addr)
	})
	return st.ctrl, st.ctrlErr
}

// Run opens the main window and blocks until the operator closes it.
func Run(cfg Config) error {
	if cfg.StreamDial == nil || cfg.CtrlDial == nil {
		return errors.New("ui: nil stream or ctrl dial")
	}
	if cfg.Session == "" {
		cfg.Session = "General"
	}

	a := app.NewWithID("io.grfx.netchat")
	w := a.NewWindow("net-chat")

	st := &state{
		session:  cfg.Session,
		address:  cfg.Address,
		peers:    make(map[string]*peer),
		peerList: binding.NewStringList(),
	}

	// Status bar comes first so button handlers can reference it.
	status := widget.NewLabel("connecting…")

	// --- Session picker ------------------------------------------
	sessionSelect := widget.NewSelect(nil, nil)
	sessionSelect.PlaceHolder = "(loading sessions…)"
	refreshBtn := widget.NewButton("Refresh", nil)

	// --- Message log ---------------------------------------------
	// Explicit-callback List so each row can render a 4-px colored
	// bar on the leading edge (canvas.Rectangle) plus the wrapped
	// message text. Colour is derived at bind time from the sender
	// via colorForSender's stable hash.
	msgList := widget.NewList(
		func() int {
			st.mu.Lock()
			defer st.mu.Unlock()
			return len(st.msgs)
		},
		func() fyne.CanvasObject {
			bar := canvas.NewRectangle(color.Transparent)
			bar.SetMinSize(fyne.NewSize(4, 0))
			l := widget.NewLabel("")
			l.Wrapping = fyne.TextWrapWord
			// Placeholder QR image widget — always present in the
			// template so the widget tree shape stays stable across
			// binds. Sized 0×0 by default; the update callback swaps
			// in the QR image and grows the MinSize when the body
			// carries a WIFI:...;; URI.
			img := canvas.NewImageFromImage(nil)
			img.FillMode = canvas.ImageFillOriginal
			img.SetMinSize(fyne.NewSize(0, 0))
			content := container.NewVBox(l, img)
			return container.NewBorder(nil, nil, bar, nil, content)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			st.mu.Lock()
			var m messageEntry
			if id >= 0 && id < len(st.msgs) {
				m = st.msgs[id]
			}
			st.mu.Unlock()
			box := obj.(*fyne.Container)
			// container.NewBorder puts CENTER objects FIRST in the
			// slice, then top/bottom/left/right in that order — see
			// container/layouts.go line 26-45. Our shape is
			// (left=bar, center=content); Objects[0]=content
			// (VBox), Objects[1]=bar.
			vbox := box.Objects[0].(*fyne.Container)
			bar := box.Objects[1].(*canvas.Rectangle)
			label := vbox.Objects[0].(*widget.Label)
			img := vbox.Objects[1].(*canvas.Image)
			bar.FillColor = colorForSender(m.sender)
			bar.Refresh()
			label.SetText(formatMessageStruct(m))
			// QR image renders inline ONLY when the row is fully
			// visible (not folded) AND the body carries a WIFI URI.
			// A folded row with a WIFI URI hides the QR too, so the
			// [+] affordance keeps its "click to see more" meaning.
			var qrImg image.Image
			if !m.folded {
				qrImg = renderQR(firstWifiURI(m.body))
			}
			if qrImg != nil {
				img.Image = qrImg
				img.SetMinSize(fyne.NewSize(160, 160))
			} else {
				img.Image = nil
				img.SetMinSize(fyne.NewSize(0, 0))
			}
			img.Refresh()
		},
	)
	// Click a foldable row to toggle its fold state.
	msgList.OnSelected = func(id widget.ListItemID) {
		msgList.Unselect(id)
		st.mu.Lock()
		if id < 0 || id >= len(st.msgs) {
			st.mu.Unlock()
			return
		}
		if st.msgs[id].foldable() {
			st.msgs[id].folded = !st.msgs[id].folded
		}
		st.mu.Unlock()
		msgList.Refresh()
	}

	// --- Compose bar ---------------------------------------------
	entry := widget.NewMultiLineEntry()
	entry.SetPlaceHolder("Type a message. Send targets the current session.")
	entry.SetMinRowsVisible(2)

	sendBtn := widget.NewButton("Send", func() {
		text := entry.Text
		if text == "" {
			return
		}
		st.mu.Lock()
		target := st.session
		st.mu.Unlock()
		entry.SetText("")

		// bitchat-mesh routes: @HEX16: prefix → PostDM, else
		// PostPublic. Fully bypasses net-mgr's Ctrl connection.
		if target == meshSession && cfg.Mesh != nil {
			go func() {
				peerID, body, ok := extractMeshDMPrefix(text)
				var err error
				if ok {
					err = cfg.Mesh.PostDM(peerID, body)
				} else {
					err = cfg.Mesh.PostPublic(text)
				}
				if err != nil {
					fyne.Do(func() { dialog.ShowError(err, w) })
				}
			}()
			return
		}

		go func() {
			ctrl, err := st.getCtrl(cfg.CtrlDial)
			if err != nil {
				fyne.Do(func() {
					dialog.ShowError(fmt.Errorf("open ctrl connection: %w", err), w)
				})
				return
			}
			if _, perr := ctrl.Post(target, text); perr != nil {
				fyne.Do(func() { dialog.ShowError(perr, w) })
			}
		}()
	})

	uploadBtn := widget.NewButton("Upload…", func() {
		st.mu.Lock()
		target := st.session
		st.mu.Unlock()
		fd := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
			if err != nil || rc == nil {
				return
			}
			defer rc.Close()
			name := rc.URI().Name()
			status.SetText(fmt.Sprintf("uploading %s → %s…", name, target))
			go func() {
				ctrl, err := st.getCtrl(cfg.CtrlDial)
				if err != nil {
					fyne.Do(func() {
						dialog.ShowError(fmt.Errorf("open ctrl connection: %w", err), w)
					})
					return
				}
				size, err := ctrl.ChatPut(target, name, rc)
				fyne.Do(func() {
					if err != nil {
						dialog.ShowError(err, w)
						return
					}
					status.SetText(fmt.Sprintf("uploaded %s (%d bytes) to %q",
						name, size, target))
				})
			}()
		}, w)
		fd.Show()
	})

	filesBtn := widget.NewButton("Files…", func() {
		st.mu.Lock()
		target := st.session
		st.mu.Unlock()
		go func() {
			ctrl, err := st.getCtrl(cfg.CtrlDial)
			if err != nil {
				fyne.Do(func() {
					dialog.ShowError(fmt.Errorf("open ctrl connection: %w", err), w)
				})
				return
			}
			fyne.Do(func() { showFilesDialog(w, ctrl, target, status) })
		}()
	})

	// --- Peer roster (right panel) -------------------------------
	// Displays peers by "nickname (peer_id) [conn]" — click to
	// prepend `@<peer_id>: ` to the compose entry when we're on
	// the bitchat-bridge session. Any other session, the click is a
	// no-op with a status hint so the operator understands why.
	peerListW := widget.NewListWithData(st.peerList,
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(item binding.DataItem, obj fyne.CanvasObject) {
			s, _ := item.(binding.String).Get()
			obj.(*widget.Label).SetText(s)
		},
	)
	peerListW.OnSelected = func(id widget.ListItemID) {
		peerListW.Unselect(id)
		st.mu.Lock()
		if id < 0 || id >= len(st.peerOrder) {
			st.mu.Unlock()
			return
		}
		pid := st.peerOrder[id]
		session := st.session
		st.mu.Unlock()
		if session != bridgeSession {
			// Silently switch to bitchat-bridge — the operator's
			// intent is clear (they clicked a peer to DM them).
			sessionSelect.SetSelected(bridgeSession)
			// SetSelected fires OnChanged asynchronously via the
			// switchSession handler; the compose prep is idempotent
			// so setting the entry text now is safe.
		}
		prefix := "@" + pid + ": "
		if !strings.HasPrefix(entry.Text, prefix) {
			entry.SetText(prefix + entry.Text)
		}
		entry.CursorRow = 0
		entry.CursorColumn = len(entry.Text)
		w.Canvas().Focus(entry)
	}

	peerHeader := widget.NewLabelWithStyle("BitChat peers",
		fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	peerPanel := container.NewBorder(peerHeader, nil, nil, nil, peerListW)

	// --- Assembly ------------------------------------------------
	// connectBtn is created further down (needs `connect` closure);
	// placeholder Container swaps it in on first render.
	topBarConnect := container.NewHBox()
	topBar := container.NewBorder(nil, nil,
		widget.NewLabel("Session:"),
		container.NewHBox(refreshBtn, topBarConnect),
		sessionSelect,
	)
	// File-transfer buttons sit to the LEFT of the compose entry so
	// Send stays on the right where operators expect it. Both
	// buttons act on the currently-selected session.
	fileBtns := container.NewHBox(uploadBtn, filesBtn)
	compose := container.NewBorder(nil, nil, fileBtns, sendBtn, entry)
	body := container.NewHSplit(msgList, peerPanel)
	body.SetOffset(0.72)
	content := container.NewBorder(
		container.NewVBox(topBar, status),
		compose, nil, nil, body,
	)
	w.SetContent(content)
	w.Resize(fyne.NewSize(900, 600))

	// --- Session switch ------------------------------------------
	switchSession := func(name string) {
		st.mu.Lock()
		if name == st.session && st.chatSubID != "" {
			st.mu.Unlock()
			return
		}
		oldSub := st.chatSubID
		st.chatSubID = ""
		st.session = name
		st.mu.Unlock()

		st.mu.Lock()
		stream := st.stream
		st.mu.Unlock()
		if oldSub != "" && stream != nil {
			_ = stream.Unsubscribe(oldSub)
		}
		st.mu.Lock()
		st.msgs = nil
		st.snapshotDone = false // new session's snapshot rows fold again
		st.mu.Unlock()
		msgList.Refresh()
		msgList.ScrollToTop()
		status.SetText(fmt.Sprintf("switching to %q…", name))

		// bitchat-mesh is fed by cfg.Mesh's AppEvents in a separate
		// goroutine (started in Run below). Don't fire a net-mgr
		// SUBSCRIBE for it.
		if name == meshSession {
			status.SetText("bitchat mesh — live")
			return
		}

		if stream == nil {
			return // not connected yet — Connect… will re-subscribe
		}
		// Kick the SUBSCRIBE off a goroutine so a slow network I/O
		// call doesn't freeze the UI thread that fired OnChanged.
		go func() {
			sub, err := stream.SubscribeChat(name)
			fyne.Do(func() {
				if err != nil {
					status.SetText("subscribe: " + err.Error())
					return
				}
				st.mu.Lock()
				st.chatSubID = sub
				st.mu.Unlock()
				status.SetText(fmt.Sprintf("subscribed to %q (sub=%s)…", name, sub))
			})
		}()
	}
	sessionSelect.OnChanged = func(name string) {
		if name != "" {
			switchSession(name)
		}
	}

	// Seed picker at launch with the initial session + bridgeSession
	// so the operator has SOMETHING to interact with before ctrl is
	// open. Refresh replaces with the full list once ctrl is up.
	seed := []string{cfg.Session}
	if !contains(seed, bridgeSession) {
		seed = append(seed, bridgeSession)
	}
	if cfg.Mesh != nil && !contains(seed, meshSession) {
		seed = append(seed, meshSession)
	}
	sort.Strings(seed)
	sessionSelect.Options = seed
	sessionSelect.SetSelected(cfg.Session)

	// --- Session list load / refresh -----------------------------
	// forceDial=true means the operator explicitly asked (Refresh
	// button) and is OK with the potential ssh-keygen prompt. On
	// startup we pass forceDial=false so ctrl stays deferred.
	loadSessions := func(forceDial bool) {
		go func() {
			var ctrl *netmgr.Client
			st.mu.Lock()
			ctrl = st.ctrl
			st.mu.Unlock()
			if ctrl == nil {
				if !forceDial {
					return
				}
				var err error
				ctrl, err = st.getCtrl(cfg.CtrlDial)
				if err != nil {
					fyne.Do(func() { status.SetText("open ctrl: " + err.Error()) })
					return
				}
			}
			rows, err := ctrl.ListChatSessions(false)
			if err != nil {
				fyne.Do(func() { status.SetText("session list: " + err.Error()) })
				return
			}
			names := extractSessionNames(rows)
			if !contains(names, bridgeSession) {
				names = append(names, bridgeSession)
				sort.Strings(names)
			}
			if !contains(names, st.session) {
				names = append(names, st.session)
				sort.Strings(names)
			}
			fyne.Do(func() {
				sessionSelect.Options = names
				sessionSelect.Refresh()
				if sessionSelect.Selected == "" {
					sessionSelect.SetSelected(st.session)
				}
			})
		}()
	}
	refreshBtn.OnTapped = func() { loadSessions(true) }

	// connect (re)dials the stream connection to addr, then kicks off
	// the read loop + initial subscribes. Called on Run() startup with
	// cfg.Address, and again whenever the operator confirms a new
	// address in the Connect… dialog. Any prior connection + readLoop
	// is torn down first.
	var connect func(addr string)
	connect = func(addr string) {
		st.mu.Lock()
		if st.cancel != nil {
			st.cancel()
		}
		if st.stream != nil {
			_ = st.stream.Close()
			st.stream = nil
		}
		st.chatSubID = ""
		st.peerSubID = ""
		st.address = addr
		st.mu.Unlock()

		if addr == "" {
			status.SetText("not connected — hit Connect…")
			return
		}
		status.SetText("connecting to " + addr + "…")
		go func() {
			stream, err := cfg.StreamDial(addr)
			if err != nil {
				fyne.Do(func() {
					status.SetText("connect: " + err.Error())
					dialog.ShowError(err, w)
				})
				return
			}
			st.mu.Lock()
			st.stream = stream
			ctx, cancel := context.WithCancel(context.Background())
			st.cancel = cancel
			st.mu.Unlock()

			// Read loop drains ROW/EOS/OK/ERR frames from this
			// connection. Its lifetime is scoped to ctx; a
			// subsequent connect() cancels + Close's this.
			go func() {
				if err := readLoop(ctx, stream, st, status, msgList); err != nil {
					fyne.Do(func() { status.SetText("disconnected: " + err.Error()) })
				}
			}()
			// Peer sub first so the roster fills while chat sub
			// negotiates. Non-fatal on failure.
			if sub, err := stream.SubscribeBitChatPeers(); err == nil {
				st.mu.Lock()
				st.peerSubID = sub
				st.mu.Unlock()
			} else {
				fyne.Do(func() { status.SetText("peers: " + err.Error()) })
			}
			// Initial chat sub for the picker's current session.
			st.mu.Lock()
			sess := st.session
			st.mu.Unlock()
			if sub, err := stream.SubscribeChat(sess); err == nil {
				st.mu.Lock()
				st.chatSubID = sub
				st.mu.Unlock()
				fyne.Do(func() {
					status.SetText(fmt.Sprintf("connected — %s (sub=%s)…", sess, sub))
				})
			} else {
				fyne.Do(func() {
					status.SetText("subscribe: " + err.Error())
				})
			}
			loadSessions(false)
		}()
	}

	// Connect… button opens a dialog for entering host:port. Populated
	// with the current address so a re-connect is one Enter press.
	connectBtn := widget.NewButton("Connect…", func() {
		st.mu.Lock()
		curr := st.address
		st.mu.Unlock()
		addrEntry := widget.NewEntry()
		addrEntry.SetText(curr)
		addrEntry.SetPlaceHolder("host:port (e.g. 192.168.15.104:7531)")
		dialog.ShowForm("Connect", "Connect", "Cancel",
			[]*widget.FormItem{
				{Text: "Address", Widget: addrEntry},
			},
			func(ok bool) {
				if !ok || strings.TrimSpace(addrEntry.Text) == "" {
					return
				}
				connect(strings.TrimSpace(addrEntry.Text))
			}, w)
	})

	// --- Close cleanup -------------------------------------------
	w.SetOnClosed(func() {
		st.mu.Lock()
		if st.cancel != nil {
			st.cancel()
		}
		stream := st.stream
		chatSub, peerSub := st.chatSubID, st.peerSubID
		ctrl := st.ctrl
		st.mu.Unlock()
		if stream != nil {
			for _, sub := range []string{chatSub, peerSub} {
				if sub != "" {
					_ = stream.Unsubscribe(sub)
				}
			}
			_ = stream.Close()
		}
		if ctrl != nil {
			_ = ctrl.Close()
		}
	})

	topBarConnect.Add(connectBtn)
	topBarConnect.Refresh()

	// Kick off the initial dial. If cfg.Address is blank, connect()
	// just parks in "not connected" state and waits for Connect….
	go connect(cfg.Address)

	// Start the bitchat mesh event loop when cfg.Mesh is provided.
	// The mesh service must already be Started by the caller — we
	// only consume its Events here.
	if cfg.Mesh != nil {
		go meshEventLoop(cfg.Mesh, st, msgList, status)
	}

	w.ShowAndRun()
	return nil
}

// meshEventLoop drains cfg.Mesh.Events and translates AppMessage /
// AppPeer / AppAdapter events into UI state changes. It runs for the
// life of the window; when Mesh's Events channel closes (on Close())
// the loop exits.
func meshEventLoop(m *mesh.Service, st *state, msgList *widget.List, status *widget.Label) {
	for ev := range m.Events() {
		switch e := ev.(type) {
		case mesh.AppMessage:
			// Only display when the mesh session is currently
			// selected. Otherwise skip — the mesh peer/handshake
			// state is still updated in the mesh Service; only
			// the message log is per-session.
			st.mu.Lock()
			showing := st.session == meshSession
			st.mu.Unlock()
			if !showing || e.Message == nil {
				continue
			}
			entry := messageEntry{
				sender: e.Message.Sender,
				body:   e.Message.Content,
			}
			if entry.sender == "" {
				entry.sender = e.FromID
			}
			st.mu.Lock()
			entry.folded = false
			st.msgs = append(st.msgs, entry)
			last := len(st.msgs) - 1
			st.mu.Unlock()
			fyne.Do(func() {
				msgList.Refresh()
				msgList.ScrollTo(last)
			})
		case mesh.AppPeer:
			// Merge mesh peers into the roster. Nickname empty on
			// first sighting; second Announce fills it. Display
			// suffix `[mesh]` so the UI can tell them apart from
			// net-mgr bitchat_peers ROWs.
			pid := e.PeerID
			nick := e.Nickname
			if nick == "" {
				nick = "(no nick)"
			}
			marker := " "
			if e.Connected {
				marker = "●"
			}
			display := fmt.Sprintf("%s %s (%s) [mesh]", marker, nick, pid)
			// Direct manipulation of st.peers is under st.mu.
			st.mu.Lock()
			if _, ok := st.peers[pid]; !ok {
				st.peers[pid] = &peer{peerID: pid}
				st.peerOrder = append(st.peerOrder, pid)
			}
			p := st.peers[pid]
			p.connected = e.Connected
			if e.Nickname != "" {
				p.nickname = e.Nickname
			}
			// Re-render the display list.
			out := make([]string, 0, len(st.peerOrder))
			for _, id := range st.peerOrder {
				pp := st.peers[id]
				n := pp.nickname
				if n == "" {
					n = "(no nick)"
				}
				m := " "
				if pp.connected {
					m = "●"
				}
				out = append(out, fmt.Sprintf("%s %s (%s)", m, n, id))
			}
			st.mu.Unlock()
			_ = display
			fyne.Do(func() { _ = st.peerList.Set(out) })
		case mesh.AppAdapter:
			msg := "bitchat mesh: adapter " + boolOnOff(e.PoweredOn)
			if e.Reason != "" {
				msg += " (" + e.Reason + ")"
			}
			fyne.Do(func() { status.SetText(msg) })
		}
	}
}

func boolOnOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

// extractMeshDMPrefix parses a "@<16hex>: <body>" leading prefix off
// text. On a match returns (peer_id, body, true); else ("", text, false).
// Same convention the autoresponder uses for BitChat DMs.
func extractMeshDMPrefix(text string) (peerID, body string, ok bool) {
	if !strings.HasPrefix(text, "@") {
		return "", text, false
	}
	// Expect exactly 16 hex chars then ": ".
	if len(text) < 1+16+2 {
		return "", text, false
	}
	pid := text[1:17]
	for i := 0; i < 16; i++ {
		c := pid[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", text, false
		}
	}
	if text[17] != ':' {
		return "", text, false
	}
	// Skip ": " (colon + optional space).
	rest := text[18:]
	if strings.HasPrefix(rest, " ") {
		rest = rest[1:]
	}
	return strings.ToLower(pid), rest, true
}

// readLoop drains the connection until ctx is cancelled or the socket
// closes. Routes ROWs by table to either the message list or the peer
// roster. Frame types other than ROW/EOS/OK/ERR are ignored — this
// scaffold doesn't yet do the CHAT_* control replies.
func readLoop(ctx context.Context, c *netmgr.Client, st *state,
	status *widget.Label, msgList *widget.List) error {

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		cmd, raw, err := c.Recv()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return err
		}
		if cmd == nil {
			continue
		}
		switch cmd.Verb {
		case "ROW":
			handleRow(cmd.KV, st, msgList)
		case "EOS":
			// One EOS per SUBSCRIBE snapshot end. If it's for the
			// chat sub, flip snapshotDone so subsequent (live) rows
			// arrive unfolded.
			st.mu.Lock()
			eosSub := cmd.KV["sub"]
			if eosSub != "" && eosSub == st.chatSubID {
				st.snapshotDone = true
			}
			st.mu.Unlock()
			fyne.Do(func() {
				status.SetText(fmt.Sprintf("live @ %s",
					time.Now().Format("15:04:05")))
			})
		case "ERR":
			fyne.Do(func() { status.SetText("daemon ERR: " + raw) })
		}
	}
}

// handleRow demuxes ROW frames by table.
func handleRow(kv map[string]string, st *state, msgList *widget.List) {
	switch kv["table"] {
	case "chat_messages":
		st.mu.Lock()
		activeSub := st.chatSubID
		st.mu.Unlock()
		// Filter by chat sub id in case a stale UNSUB is still
		// in flight from a session switch.
		if kv["sub"] != "" && activeSub != "" && kv["sub"] != activeSub {
			return
		}
		m := messageEntry{sender: kv["sender"], body: kv["body"]}
		if m.sender == "" {
			m.sender = "?"
		}
		// Filter chatter: bridge heartbeats (sender=local, body
		// starts with "[bridge] online" or similar) flood the log
		// with hundreds of near-duplicates. Skip them silently.
		if isNoisyBridgeHeartbeat(m) {
			return
		}
		st.mu.Lock()
		// Historical (pre-EOS) rows default to folded so a big
		// snapshot doesn't blow up the message log height. Live
		// rows arrive unfolded — the operator explicitly wants to
		// see them. Matches Perl bin/net-chat's fold-on-prepend /
		// unfold-on-append convention.
		m.folded = !st.snapshotDone && m.foldable()
		st.msgs = append(st.msgs, m)
		last := len(st.msgs) - 1
		st.mu.Unlock()
		fyne.Do(func() {
			msgList.Refresh()
			msgList.ScrollTo(last)
		})
	case "bitchat_peers":
		updatePeer(kv, st)
	}
}

// updatePeer merges a bitchat_peers ROW into the roster state and
// rebuilds the display list.
func updatePeer(kv map[string]string, st *state) {
	pid := kv["peer_id"]
	if pid == "" {
		return
	}
	op := kv["op"]
	st.mu.Lock()
	defer st.mu.Unlock()
	if op == "delete" {
		delete(st.peers, pid)
		st.peerOrder = removeString(st.peerOrder, pid)
	} else {
		p, ok := st.peers[pid]
		if !ok {
			p = &peer{peerID: pid}
			st.peers[pid] = p
			st.peerOrder = append(st.peerOrder, pid)
		}
		if v, has := kv["nickname"]; has {
			p.nickname = v
		}
		if v, has := kv["is_connected"]; has {
			p.connected = v == "1" || strings.EqualFold(v, "true")
		}
		if v, has := kv["last_seen"]; has {
			p.lastSeen = v
		}
	}
	sort.SliceStable(st.peerOrder, func(i, j int) bool {
		pi := st.peers[st.peerOrder[i]]
		pj := st.peers[st.peerOrder[j]]
		// Connected peers first, then by nickname, then by peer_id.
		if pi.connected != pj.connected {
			return pi.connected
		}
		if pi.nickname != pj.nickname {
			return pi.nickname < pj.nickname
		}
		return pi.peerID < pj.peerID
	})
	display := make([]string, 0, len(st.peerOrder))
	for _, id := range st.peerOrder {
		p := st.peers[id]
		nick := p.nickname
		if nick == "" {
			nick = "(no nick)"
		}
		marker := " "
		if p.connected {
			marker = "●"
		}
		display = append(display, fmt.Sprintf("%s %s (%s)", marker, nick, id))
	}
	fyne.Do(func() { _ = st.peerList.Set(display) })
}

func formatMessageStruct(m messageEntry) string {
	return m.sender + ": " + m.displayBody()
}

// isNoisyBridgeHeartbeat matches the "[bridge] online nick=<host>..."
// (and its offline sibling) rows that the local bridge posts as
// operational chatter. They arrive with sender=local and are useful
// exactly zero times to a human reading the log — filter them out
// before they hit the message list. Uses a simple prefix match on the
// canonical shape rather than a regex so the check is cheap on every
// row.
func isNoisyBridgeHeartbeat(m messageEntry) bool {
	if m.sender != "local" {
		return false
	}
	// Canonical prefixes the bridge posts:
	//   [bridge] online nick=<host> peer_id=<hex>
	//   [bridge] offline nick=<host> peer_id=<hex>
	// The " online" / " offline" step is the discriminator so we
	// don't accidentally squash a genuine "[bridge] <error>" post
	// that an operator might want to see.
	return strings.HasPrefix(m.body, "[bridge] online") ||
		strings.HasPrefix(m.body, "[bridge] offline")
}

// showFilesDialog fetches the current file list for session and pops
// a Toplevel with a scrollable table. Click a row to save via ChatGet
// to a location chosen through a native Save dialog. Runs on a
// goroutine so a slow CHAT_LS doesn't freeze the UI.
func showFilesDialog(w fyne.Window, ctrl *netmgr.Client, session string,
	status *widget.Label) {

	files, err := ctrl.ChatLs(session)
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	if len(files) == 0 {
		dialog.ShowInformation("Files",
			fmt.Sprintf("no files in %q", session), w)
		return
	}
	list := widget.NewList(
		func() int { return len(files) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			f := files[id]
			obj.(*widget.Label).SetText(
				fmt.Sprintf("%-32s %10d bytes", f.Name, f.Size))
		},
	)
	d := dialog.NewCustom("Files in "+session, "Close",
		container.NewGridWrap(fyne.NewSize(520, 320), list), w)
	list.OnSelected = func(id widget.ListItemID) {
		list.Unselect(id)
		if id < 0 || id >= len(files) {
			return
		}
		name := files[id].Name
		fd := dialog.NewFileSave(func(rc fyne.URIWriteCloser, err error) {
			if err != nil || rc == nil {
				return
			}
			go func() {
				defer rc.Close()
				fyne.Do(func() {
					status.SetText(fmt.Sprintf("downloading %s…", name))
				})
				n, gerr := ctrl.ChatGet(session, name, rc)
				fyne.Do(func() {
					if gerr != nil {
						dialog.ShowError(gerr, w)
						return
					}
					status.SetText(fmt.Sprintf(
						"downloaded %s → %s (%d bytes)",
						name, rc.URI().Path(), n))
				})
			}()
			d.Hide()
		}, w)
		fd.SetFileName(name)
		fd.Show()
	}
	d.Show()
}

func extractSessionNames(rows []map[string]string) []string {
	names := make([]string, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for _, r := range rows {
		n := r["name"]
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func removeString(ss []string, s string) []string {
	for i, v := range ss {
		if v == s {
			return append(ss[:i], ss[i+1:]...)
		}
	}
	return ss
}
