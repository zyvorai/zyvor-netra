.PHONY: test build build-cli web bpf fmt test-python test-tlsfp test-p1-p5 test-features test-netractl-commands test-netractl-live install uninstall

# Destination for `make install` (override: make install PREFIX=$HOME/.local).
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=

fmt:
	gofmt -w cmd internal

test:
	go test ./...

test-tlsfp:
	./scripts/ci-tlsfp-unit.sh

test-p1-p5:
	./scripts/ci-p1-p5-unit.sh

test-features:
	./scripts/ci-features-unit.sh

test-netractl-commands:
	./scripts/ci-netractl-commands.sh

test-netractl-live:
	./scripts/ci-netractl-live.sh

# Optional companion; no pip packages required for the linear runner.
test-python:
	PYTHONPATH=python python3 -m unittest discover -s python/tests -v

# Build operator CLI into ./bin (used by install and deploy-remote).
build-cli:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/netractl ./cmd/netractl

# Install netractl onto PATH: make install  or  make install PREFIX=$$HOME/.local
install: build-cli
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 755 bin/netractl "$(DESTDIR)$(BINDIR)/netractl"
	@echo "installed $(DESTDIR)$(BINDIR)/netractl"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/netractl"
	@echo "removed $(DESTDIR)$(BINDIR)/netractl"

build: web
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/netrad ./cmd/netrad
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/netractl ./cmd/netractl
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/netra-agent ./cmd/netra-agent
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/netra-doctor ./cmd/netra-doctor

web:
	npm --prefix web install
	npm --prefix web run build

bpf:
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -mllvm -bpf-stack-size=1024 -c bpf/netra_tc.c -o bpf/netra_tc.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_edge_intel.c -o bpf/netra_edge_intel.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_capture.c -o bpf/netra_capture.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_tlsfp.c -o bpf/netra_tlsfp.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_tcpevents.c -o bpf/netra_tcpevents.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_dropinfo.c -o bpf/netra_dropinfo.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_nodeiso.c -o bpf/netra_nodeiso.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_l7sample.c -o bpf/netra_l7sample.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_ssl.c -o bpf/netra_ssl.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_rtnl.c -o bpf/netra_rtnl.o
