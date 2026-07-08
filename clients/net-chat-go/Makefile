# net-chat-go — build targets
#
# Native dev loop:
#   make build     # ./bin/net-chat
#   make test      # go test ./...
#   make run       # go run ./cmd/net-chat
#
# Cross-compile:
#   make windows   # bin/net-chat.exe (Windows GUI subsystem)
#   make android   # bin/net-chat.apk via fyne package (needs Android SDK+NDK)
#
# Android build assumes `go install fyne.io/fyne/v2/cmd/fyne@latest` has run
# and $ANDROID_HOME / $ANDROID_NDK_HOME are set. Easiest path is fyne-cross:
#   go install github.com/fyne-io/fyne-cross@latest
#   fyne-cross android -app-id io.grfx.netchat .

BIN := bin
PKG := ./cmd/net-chat

.PHONY: all build test vet fmt run windows android clean

all: build

$(BIN):
	mkdir -p $(BIN)

build: $(BIN)
	go build -o $(BIN)/net-chat $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

run:
	go run $(PKG)

windows: $(BIN)
	GOOS=windows GOARCH=amd64 go build -ldflags "-H windowsgui" \
		-o $(BIN)/net-chat.exe $(PKG)

# Requires: go install fyne.io/fyne/v2/cmd/fyne@latest
android: $(BIN)
	fyne package -os android -appID io.grfx.netchat -sourceDir $(PKG)
	mv net-chat.apk $(BIN)/net-chat.apk

clean:
	rm -rf $(BIN)
