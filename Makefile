.PHONY: gen
gen:
	buf generate

.PHONY: test
test: gen
	ginkgo ./...