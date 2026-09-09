.PHONY: test bundle validate init deploy ready probe exploit harden verify destroy
export CHECKPOINT_DISABLE=1
export TF_IN_AUTOMATION=true
TF=terraform -chdir=terraform

test:
	python3 -m unittest discover -s tests -v
	for script in scripts/*.sh; do bash -n "$$script"; done
bundle:
	python3 scripts/build_bundle.py
validate: test bundle
	terraform fmt -check -recursive
	terraform -chdir=bootstrap init -backend=false -input=false
	terraform -chdir=bootstrap validate
	$(TF) init -backend=false -input=false
	$(TF) validate
	$(TF) test
init:
	$(TF) init -backend-config=backend.hcl
# Human CLI use retains plan confirmation. GitHub manual workflow applies automatically.
deploy: bundle
	$(TF) apply
ready:
	python3 scripts/operations.py ready
probe:
	python3 scripts/operations.py scenario --scenario probe --confirm-lab
exploit:
	python3 scripts/operations.py scenario --scenario exploit --confirm-lab
harden: bundle
	$(TF) apply -var='app_mode=hardened'
verify:
	python3 scripts/operations.py scenario --scenario verify --confirm-lab
# Safe default: nonempty/versioned buckets block deletion. See documented explicit PURGE workflow.
destroy:
	$(TF) destroy
