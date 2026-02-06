build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -ldflags "-w -s" -trimpath -o bin/runner ./cmd/policy-agent

lint:
	golangci-lint run

unit:
	go test -count=1 $(shell go list ./... | grep -v ./integration) -vet=off -cover -coverprofile=coverage.out

generate:
	./scripts/delete_fakes.sh
	go generate ./...

image:
ifeq (${SKIP_BUILD_IMAGE},true)
	@echo "Skipping image build (SKIP_BUILD_IMAGE=true)"
else
	docker build -t policy-agent:latest .
endif

kind: certs
	kind create cluster --name policy-agent --config="./integration/fixtures/values-files/kind.yaml"
	kubectl create secret generic policy-agent \
	  --from-file=tls.crt=./certs/agent-certs/tls.crt \
	  --from-file=tls.key=./certs/agent-certs/tls.key \
	  --from-file=ca.crt=./certs/ca/ca.crt \
	  --namespace default
	kubectl create secret generic policy-server \
	  --from-file=tls.crt=./certs/server-certs/tls.crt \
	  --from-file=tls.key=./certs/server-certs/tls.key \
	  --from-file=ca.crt=./certs/ca/ca.crt \
	  --namespace default
	kubectl create secret generic postgres-tls \
	  --from-file=tls.crt=./certs/postgres-tls/tls.crt \
	  --from-file=tls.key=./certs/postgres-tls/tls.key \
	  --from-file=ca.crt=./certs/ca/ca.crt \
	  --namespace default

delete-kind:
	kind delete cluster --name policy-agent

load-kind: image
	kind load docker-image policy-agent:latest --name policy-agent

install:
	kubectl create namespace cf-workloads --dry-run=client -o yaml | kubectl apply -f - # idempotent namespace creation
	helm upgrade --install --repo https://helm.cilium.io/ cilium cilium --version v1.18.4 --namespace kube-system --wait --values ./integration/fixtures/values-files/cilium-values.yaml
	kubectl create configmap postgres-init-scripts --from-file=./integration/fixtures/db-init-scripts/ -n default --dry-run=client -o yaml | kubectl apply -f - # idempotent configmap creation
	helm upgrade --install postgres oci://registry-1.docker.io/bitnamicharts/postgresql --values ./integration/fixtures/values-files/postgres-values.yaml --wait --namespace default
	helm upgrade --install dev ./helm --values ./integration/fixtures/values-files/policy-agent.yaml --wait --namespace default
	kubectl apply -f ./integration/fixtures/manifests

certs:
	mkdir -p certs/ca certs/server-certs certs/agent-certs certs/postgres-tls
	openssl req -x509 -newkey rsa:4096 -keyout ./certs/ca/ca.key -out certs/ca/ca.crt -days 365 -nodes -subj "/CN=policy-ca/O=policy-ca" > /dev/null 2>&1
	openssl req -newkey rsa:4096 -keyout ./certs/agent-certs/tls.key -out ./certs/agent-certs/tls.csr -nodes -subj "/CN=policy-agent/O=policy-agent" > /dev/null 2>&1
	openssl x509 -req -in ./certs/agent-certs/tls.csr -CA ./certs/ca/ca.crt -CAkey ./certs/ca/ca.key -CAcreateserial -out ./certs/agent-certs/tls.crt -days 365 > /dev/null 2>&1
	openssl req -newkey rsa:4096 -keyout ./certs/server-certs/tls.key -out ./certs/server-certs/tls.csr -nodes -subj "/CN=policy-server/O=policy-server" -addext "subjectAltName=DNS:policy-server.default.svc.cluster.local" > /dev/null 2>&1
	echo "subjectAltName=DNS:policy-server.default.svc.cluster.local" > ./certs/server-certs/san.ext
	openssl x509 -req -in ./certs/server-certs/tls.csr -CA ./certs/ca/ca.crt -CAkey ./certs/ca/ca.key -CAcreateserial -out ./certs/server-certs/tls.crt -days 365 -extfile ./certs/server-certs/san.ext > /dev/null 2>&1
	openssl req -newkey rsa:4096 -keyout ./certs/postgres-tls/tls.key -out ./certs/postgres-tls/tls.csr -nodes -subj "/CN=postgres-postgresql/O=postgres-postgresql" -addext "subjectAltName=DNS:postgres-postgresql" > /dev/null 2>&1
	echo "subjectAltName=DNS:postgres-postgresql" > ./certs/postgres-tls/san.ext
	openssl x509 -req -in ./certs/postgres-tls/tls.csr -CA ./certs/ca/ca.crt -CAkey ./certs/ca/ca.key -CAcreateserial -out ./certs/postgres-tls/tls.crt -days 365 -extfile ./certs/postgres-tls/san.ext > /dev/null 2>&1

integration: kind load-kind install
	go test -v -count=1 ./integration/... -vet=off -args --ginkgo.randomize-all
	@$(MAKE) delete-kind

.PHONY: build image unit lint generate kind delete-kind load-kind install integration certs
