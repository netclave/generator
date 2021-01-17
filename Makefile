GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
TARGETOS := $(if $(TARGETOS),$(TARGETOS),linux)
TARGETARCH := $(if $(TARGETARCH),$(TARGETARCH),amd64)
TARGETGOARM := $(if $(TARGETGOARM),$(TARGETGOARM),)
BRANCH := $(if $(BRANCH),$(BRANCH),${GIT_BRANCH})
GOPRIVATE := $(if $(GOPRIVATE),$(GOPRIVATE),"github.com")
DEFAULT_COMPILER := "gcc"
COMPILER := $(if $(COMPILER),"$(COMPILER)",${DEFAULT_COMPILER})

export GOOS=$(TARGETOS)
export GOARCH=$(TARGETARCH)
export GOARM=$(TARGETGOARM)

SERVER_OUT := "bin/server-${TARGETOS}-${TARGETARCH}"
CLIENT_OUT := "bin/client-${TARGETOS}-${TARGETARCH}"
PKG := "github.com/netclave/generator"
SERVER_PKG_BUILD := "${PKG}/server"
CLIENT_PKG_BUILD := "${PKG}/client"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)

.PHONY: all server client

all: server client

dep:
	@GOPRIVATE=$(GOPRIVATE) go get -v -d ./...
	-GOPRIVATE=$(GOPRIVATE) go get github.com/netclave/apis@${BRANCH}
	-GOPRIVATE=$(GOPRIVATE) go get github.com/netclave/common@${BRANCH}
	-GOPRIVATE=$(GOPRIVATE) go get github.com/netclave/bluetooth-library@${BRANCH}

server: dep ## Build the binary file for server
	GOPRIVATE=$(GOPRIVATE) CGO_ENABLED=1 CC=${COMPILER} go build -ldflags '-s' -i -v -o $(SERVER_OUT) $(SERVER_PKG_BUILD)

client: dep ## Build the binary file for client
	@GOPRIVATE=$(GOPRIVATE) CGO_ENABLED=1 CC=${COMPILER} go build -ldflags '-s' -i -v -o $(CLIENT_OUT) $(CLIENT_PKG_BUILD)

clean: ## Remove previous builds
	@rm $(SERVER_OUT) $(CLIENT_OUT) $(API_OUT) $(API_REST_OUT) $(API_SWAG_OUT)

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
