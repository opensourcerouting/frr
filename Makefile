.PHONY: help
help: # Show help for each of the Makefile commands.
	@grep -E '^[a-zA-Z0-9 -]+:.*#'  Makefile | sort | while read -r l; do printf "\033[1;32m$$(echo $$l | cut -f 1 -d':')\033[00m\t\t\n$$(echo $$l | cut -f 2- -d'#')\n\n"; done

VAGRANT_STATUS 	:= $(shell vagrant status --machine-readable | awk -F',' '{ print $$4 }')
v   		 	:= vagrant
vu  			:= $(v) up
vh 				:= $(v) halt
vr 				:= $(v) reload
vs 				:= $(v) ssh
vsc 			:= $(vs) -c
t 				:= ./run_userns.sh --frr-builddir=$(FRR_BUILD_PATH) --log-cli-level=DEBUG -v -v -x
st 				:= python -m pytest
cwd 			:= cd /home/vagrant/dev/topotato
FRR_BUILD_PATH	:= /home/vagrant/frr

ifeq ($(VAGRANT_STATUS),running)
	ENVIRONMENT := vagrant
else
	ENVIRONMENT := host
	FRR_BUILD_PATH := $(shell echo $$FRR_BUILD_PATH)
endif

vagrant-build: # Setup vagrant for local development.
	$(vu) --provision

vagrant-reload: # Reload vagrant configuration.
	$(vr)
	$(vs)

vagrant-start: # Start vagrant.
	$(vu)

vagrant-bash: # Enter vagrant shell.
	$(vsc) '$(cwd) && bash'

exec: # Execute command inside vagrant.
ifeq ($(ENVIRONMENT),vagrant)
	$(vsc) '$(filter-out $@,$(MAKECMDGOALS))'
else
	@echo "Command only available in Vagrant environment"
endif

test: # Run topotato test inside vagrant (if running) or host. Ex. `make test` (to run all) or `make test file_name.py`.
ifeq ($(ENVIRONMENT),vagrant)
	$(vsc) '$(cwd) && $(t) $(filter-out $@,$(MAKECMDGOALS))'
else
ifndef FRR_BUILD_PATH
	@echo "FRR_BUILD_PATH is not set"
	@echo "Run:"

	@echo "export FRR_BUILD_PATH='/path/to/frr'"

else
	$(t) $(filter-out $@,$(MAKECMDGOALS))
endif
endif


selftest: # Run topotato selftests test inside vagrant (if running) or host. Example: `make selftest` (to run all) or `make selftest file_name.py`.
ifeq ($(ENVIRONMENT),vagrant)
	$(vsc) '$(cwd) && $(st) $(filter-out $@,$(MAKECMDGOALS))'
else
	$(st) $(filter-out $@,$(MAKECMDGOALS))
endif

%:
	@:
