.PHONY: typecheck test local
typecheck:
	npm run typecheck
test:
	npm test
local: typecheck test
