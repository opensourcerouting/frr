from topotato import *
"""
Test if default-originate works without route-map.

"""

@topology_fixture()
def allproto_topo(topo):
  """
  [ r1 ]
    |
  { s1 }
    |
  [ r2 ]
  
  """
  topo.router("r1").lo_ip4.append("172.16.255.254/32")
  topo.router("r1").iface_to("s1").ip4.append("192.168.255.1/24")
  topo.router("r2").iface_to("s1").ip4.append("192.168.255.2/24")

class Configs(FRRConfigs):
  routers = ["r1", "r2"]
    
  zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    interface lo
     ip address {{ routers.r1.lo_ip4[0] }} 
    !
    #%   endif
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }} 
    !
    #%   endfor
    ip forwarding
    !
    #% endblock
    """
    
  bgpd = """
  #% block main
    #%   if router.name == 'r2'
    router bgp 65001
      no bgp ebgp-requires-policy
      neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as 65000
      neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers 3 10
      exit-address-family
    !
    #%   elif router.name == 'r1'
    router bgp 65000
      no bgp ebgp-requires-policy
      neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as 65001
      neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} timers 3 10
      address-family ipv4 unicast
        neighbor 192.168.255.2 default-originate
      exit-address-family
    !
    #%   endif
  #% endblock
  """


@config_fixture(Configs)
def configs(config, allproto_topo):
    return config

@instance_fixture()
def testenv(configs):
    return FRRNetworkInstance(configs.topology, configs).prepare()
  
  
class BGPDefaultOriginate(TestBase):
    instancefn = testenv
     
    @topotatofunc
    def bgp_check_if_received(self, topo, r1, r2):
        expected = {
            str(r1.ifaces[0].ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 1}},
            }
        }
        yield from AssertVtysh.make(
            r2, "bgpd", f"show ip bgp neighbor {r1.ifaces[0].ip4[0].ip} json", maxwait=5.0, compare=expected
        )
            
    @topotatofunc
    def bgp_check_if_originated(self, topo, r1, r2):
        expected = {"ipv4Unicast": {"peers": {"192.168.255.2": {"pfxSnt": 1}}}}
        yield from AssertVtysh.make(
            r1, "bgpd", f"show ip bgp summary json", maxwait=3.0, compare=expected
        )

    @topotatofunc
    def bgp_default_route_is_valid(self, topo, r1, r2):
        expected = {"paths": [{"valid": True}]}
        yield from AssertVtysh.make(
            r2, "bgpd", f"show ip bgp 0.0.0.0/0 json", maxwait=3.0, compare=expected
        )

