# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/focal64"

  config.vm.hostname = "topotato-dev"

  config.vm.synced_folder ".", "/home/vagrant/dev/topotato", type: "virtualbox", owner: "vagrant", group: "vagrant"

  config.vm.boot_timeout = 600

  config.vm.provider "virtualbox" do |vb|
    vb.cpus = 2
    vb.memory = "2048"
  end

  # config.vm.provision "shell", inline: <<-SHELL
  #   apt-get update 
  # SHELL

  config.vbguest.auto_update = false

  config.vm.provision "shell", path: "./vm/ubuntu/install.sh"
  config.vm.provision "shell", path: "./vm/ubuntu/topotato-install.sh"

end