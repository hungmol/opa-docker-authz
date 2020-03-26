.PHONY: all build

VERSION := 0.6
GO_VERSION := 1.14.1
REPO := openpolicyagent/opa-docker-authz

all: build

build:
	@docker container run --rm \
		-e VERSION=$(VERSION) \
		-v $(PWD):/go/src/github.com/open-policy-agent/opa-docker-authz \
		-w /go/src/github.com/open-policy-agent/opa-docker-authz \
		golang:$(GO_VERSION) \
		./build.sh

image: build
	@docker image build \
		--tag $(REPO):$(VERSION) \
		.

plugin: build
	@docker container run --rm \
		-e REPO=$(REPO) \
		-e VERSION=$(VERSION) \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(PWD):/opa-docker-authz \
		-w /opa-docker-authz \
		buildpack-deps:curl \
		./plugin.sh

plugin-push:
	@for plugin in `docker plugin ls --format '{{.Name}}'`; do \
		if [ "$$plugin" = "$(REPO)-v2:$(VERSION)" ]; then \
		    echo "\nPushing plugin $(REPO)-v2:$(VERSION) ..."; \
            docker plugin push $(REPO)-v2:$(VERSION); \
			exit; \
		fi \
	done; \
	echo "\nNo local copy of $(REPO)-v2:$(VERSION) exists, create it before attempting push"

clean:
	@if [ -f ./opa-docker-authz ]; then \
		echo "\nRemoving opa-docker-authz binary ..."; \
		rm -rvf ./opa-docker-authz; \
	fi
	@for plugin in `docker plugin ls --format '{{.Name}}'`; do \
		if [ "$$plugin" = "$(REPO)-v2:$(VERSION)" ]; then \
		    echo "\nRemoving local copy of plugin $(REPO):$(VERSION) ..."; \
            docker plugin rm -f $(REPO)-v2:$(VERSION); \
		fi \
	done
