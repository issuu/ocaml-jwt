.PHONY: build
build:
	jbuilder build @install --dev

# requires odoc
.PHONY: doc
doc:
	jbuilder build @doc

.PHONY: test
test:
	jbuilder runtest --dev --force

.PHONY: all
all:
	jbuilder build @install

.PHONY: clean
clean:
	jbuilder clean
