.PHONY: fmt test lint helm-lint docker-build verify

fmt:
	gofmt -w .

test:
	go test -race -coverprofile=coverage.out ./...

lint:
	go vet ./...
	golangci-lint run

helm-lint:
	helm lint deploy/helm
	helm template k8s-policy-webhook deploy/helm --namespace k8s-policy-webhook --set certManager.enabled=true >/dev/null
	helm template k8s-policy-webhook deploy/helm --namespace k8s-policy-webhook --set certManager.enabled=false --set tls.existingSecretName=k8s-policy-webhook-tls --set webhook.caBundle=Y2EtYnVuZGxl >/dev/null

docker-build:
	docker build -t k8s-policy-webhook:local .

verify:
	hack/verify.sh
