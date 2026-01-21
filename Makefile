VAGRANT_STATUS 	:= $(shell vagrant status --machine-readable | awk -F',' '{ print $$4 }')
v   		 	:= vagrant
vu  			:= $(v) up
vh 				:= $(v) halt
vr 				:= $(v) reload
vs 				:= $(v) ssh
vsc 			:= $(vs) -c
t 				:= ./run_userns.sh --frr-builddir=$(FRR_BUILD_PATH) --log-cli-level=DEBUG -v -v -x
cwd 			:= cd /home/vagrant/dev/topotato
FRR_BUILD_PATH	:= /home/vagrant/frr

ifeq ($(VAGRANT_STATUS),running)
	ENVIRONMENT := vagrant
else
	ENVIRONMENT := host
	FRR_BUILD_PATH := $(shell echo $$FRR_BUILD_PATH)
endif

vagrant-build:
	$(vu) --provision

vagrant-reload:
	$(vr)
	$(vs)

vagrant-start:
	$(vu)

vagrant-bash:
	$(vsc) '$(cwd) && bash'

exec:
ifeq ($(ENVIRONMENT),vagrant)
	$(vsc) '$(filter-out $@,$(MAKECMDGOALS))'
else
	@echo "Command only available in Vagrant environment"
endif

test:
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

%:
	@:
