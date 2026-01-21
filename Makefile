v   := vagrant
vu  := $(v) up
vh := $(v) halt
vr := $(v) reload
vs := $(v) ssh
vsc := $(vs) -c
t := ./run_userns.sh --frr-builddir=/home/vagrant/frr --log-cli-level=DEBUG -v -v -x
cwd := cd /home/vagrant/dev/topotato
runningvmname := $(shell $(v) status | grep running | awk '{print $$1}')

build:
	$(vu) $(filter-out $@,$(MAKECMDGOALS)) --provision

reload:
	$(vr) $(filter-out $@,$(MAKECMDGOALS))
	$(vs) $(filter-out $@,$(MAKECMDGOALS))

start:
	$(vu) $(filter-out $@,$(MAKECMDGOALS))

bash:
	$(vs) $(runningvmname) -c '$(cwd) && bash'

exec:
	$(vs) $(runningvmname) -c '$(filter-out $@,$(MAKECMDGOALS))'

run:
	$(vs) $(runningvmname) -c '$(cwd) && $(t) $(filter-out $@,$(MAKECMDGOALS))'

%:
	@:
