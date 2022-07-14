from topotato import *
"""
Test if works the following commands:
router bgp 65031
  address-family ipv4 unicast
    aggregate-address 172.16.255.0/24 route-map aggr-rmap

route-map aggr-rmap permit 10
  set metric 123

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
        redistribute connected
        aggregate-address 172.16.255.0/24 route-map aggr-rmap
      exit-address-family
    !
    route-map aggr-rmap permit 10
      set metric 123
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
  
  
class BGPAggregateAddressRouteMap(TestBase):
    instancefn = testenv
    
    @topotatofunc
    def bgp_converge(self, topo, r1, r2):
        expected = {
            str(r1.ifaces[0].ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 3}},
            }
        }
        yield from AssertVtysh.make(
            r2, "bgpd", f"show ip bgp neighbor {r1.ifaces[0].ip4[0].ip} json", maxwait=5.0, compare=expected
        )
            
    @topotatofunc
    def bgp_aggregate_address_has_metric(self, topo, r1, r2):
        expected = {"paths": [{"metric": 123}]}
        yield from AssertVtysh.make(
            r2, "bgpd", f"show ip bgp 172.16.255.0/24 json", maxwait=3.0, compare=expected
        )


