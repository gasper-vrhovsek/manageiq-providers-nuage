require 'json'
describe ManageIQ::Providers::Nuage::NetworkManager::VsdClient do
  include Vmdb::Logging
  before(:each) do
    @userid = Rails.application.secrets.nuage_network.try(:[], 'userid') || 'NUAGE_USER_ID'
    @password = Rails.application.secrets.nuage_network.try(:[], 'password') || 'NUAGE_PASSWORD'
    @hostname = Rails.application.secrets.nuage_network.try(:[], 'host') || 'nuagenetworkhost'

    # Ensure that VCR will obfuscate the basic auth
    VCR.configure do |c|
      # workaround for escaping host
      c.before_playback do |interaction|
        interaction.filter!(CGI.escape(@hostname), @hostname)
        interaction.filter!(CGI.escape('NUAGE_NETWORK_HOST'), 'nuagenetworkhost')
      end
      c.filter_sensitive_data('NUAGE_NETWORK_AUTHORIZATION') { Base64.encode64("#{@userid}:#{@password}").chomp }
    end
  end

  it "should return valid non empty json response for enterprises" do
    enterprises = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/enterprises', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      enterprises = vsd_client.get_enterprises
    end

    assert_object_not_empty(enterprises)
    assert_enterprises_parameters(enterprises)
  end

  it "should return empty response for enterprises" do
    enterprises = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/enterprises_empty', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      enterprises = vsd_client.get_enterprises
    end

    expect(enterprises).to be_nil
  end

  it "should return valid non empty json response for domains" do
    domains = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/domains', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      domains = vsd_client.get_domains
    end

    assert_object_not_empty(domains)
    assert_domains_parameters(domains)
  end

  it "should return empty response for domains" do
    domains = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/domains_empty', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      domains = vsd_client.get_domains
    end

    expect(domains).to be_nil
  end

  it "should return valid non empty json response for zones" do
    zones = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/zones', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      zones = vsd_client.get_zones
    end

    assert_object_not_empty(zones)
    assert_zones_parameters(zones)
  end

  it "should return empty response for zones" do
    zones = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/zones_empty', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      zones = vsd_client.get_zones
    end

    expect(zones).to be_nil
  end

  it "should return valid non empty json response for subnets" do
    subnets = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/subnets', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      subnets = vsd_client.get_subnets
    end

    assert_object_not_empty(subnets)
    assert_subnets_parameters(subnets)
  end

  it "should return empty response for subnets" do
    subnets = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/subnets_empty', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      subnets = vsd_client.get_subnets
    end

    expect(subnets).to be_nil
  end

  it "should return valid non empty json response for vms" do
    vms = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/vms', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      vms = vsd_client.get_vms
    end
    assert_object_not_empty(vms)
    assert_vms_parameters(vms)
  end

  it "should return empty response for vms" do
    vms = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/vms_empty', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      vms = vsd_client.get_vms
    end
    expect(vms).to be_nil
  end

  it "should return valid non empty json response for policy_groups" do
    policy_groups = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/policy_groups', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      policy_groups = vsd_client.get_policy_groups
    end

    assert_object_not_empty(policy_groups)
    assert_policy_groups_parameters(policy_groups)
  end

  it "should return empty response for policy_groups" do
    policy_groups = nil
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/policy_groups_empty', :record => :new_episodes) do
      vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      policy_groups = vsd_client.get_policy_groups
    end
    expect(policy_groups).to be_nil
  end

  it "should fail on wrong password" do
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/wrong_pass', :record => :new_episodes) do
      expect do
        described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, 'wrong_password')
      end.to raise_error(MiqException::MiqInvalidCredentialsError)
    end
  end

  it "should fail on wrong username" do
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/wrong_user', :record => :new_episodes) do
      expect do
        described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", 'wrong_user', @password)
      end.to raise_error(MiqException::MiqInvalidCredentialsError)
    end
  end

  it "should fail on wrong hostname" do
    VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/wrong_hostname', :record => :new_episodes) do
      expect do
        described_class.new("https://wronghost:8443/nuage/api/v5_0", @userid, @password)
      end.to raise_error(SocketError)
    end
  end

  def assert_object_not_empty(object)
    expect(object.length).to be > 0
    expect(object.length).to be_truthy
  end

  def assert_enterprises_parameters(enterprises)
    expect(enterprises.count).to be(3)

    # test first enterprise object
    enterprise = enterprises.first
    expect(enterprise).to include(
      "children"                               => nil,
      "parentType"                             => nil,
      "entityScope"                            => "ENTERPRISE",
      "lastUpdatedBy"                          => "43f8868f-4bc1-472c-9d19-533dcfcb1ee0",
      "lastUpdatedDate"                        => 1_508_320_714_000,
      "creationDate"                           => 1_508_320_714_000,
      "name"                                   => "Ansible-Test",
      "description"                            => "Created by Ansible",
      "avatarType"                             => nil,
      "avatarData"                             => nil,
      "floatingIPsQuota"                       => 16,
      "floatingIPsUsed"                        => 0,
      "allowTrustedForwardingClass"            => false,
      "allowAdvancedQOSConfiguration"          => false,
      "allowedForwardingClasses"               => ["H"],
      "allowGatewayManagement"                 => false,
      "enableApplicationPerformanceManagement" => false,
      "encryptionManagementMode"               => "DISABLED",
      "localAS"                                => nil,
      "dictionaryVersion"                      => 2,
      "allowedForwardingMode"                  => nil,
      "owner"                                  => "d2dc3ac6-01a4-4755-8686-e0be7f36f088",
      "ID"                                     => "08ceacac-e6fb-420b-a055-231e9f39d9ab",
      "parentID"                               => nil,
      "externalID"                             => nil,
      "customerID"                             => 219_362,
      "DHCPLeaseInterval"                      => 24,
      "enterpriseProfileID"                    => "f1e5eb19-c67a-4651-90c1-3f84e23e1d36",
      "receiveMultiCastListID"                 => "081169f6-cb2f-4c6e-8e94-b701224a5141",
      "sendMultiCastListID"                    => "738446cc-026f-488f-9718-b13f4390857b",
      "associatedGroupKeyEncryptionProfileID"  => "73cbfff8-6491-421d-9efd-6a36ef5eaf1d",
      "associatedEnterpriseSecurityID"         => "2bfa4486-ef56-4c1b-8cd6-729883e62943",
      "associatedKeyServerMonitorID"           => "05fe9c44-272f-46df-8134-4bb80cccec37",
      "LDAPEnabled"                            => false,
      "LDAPAuthorizationEnabled"               => false,
      "BGPEnabled"                             => false
    )
  end

  def assert_domains_parameters(domains)
    expect(domains.count).to be(4)

    # test first domain object
    domain = domains.first

    expect(domain).to include(
      "children"                        => nil,
      "parentType"                      => "enterprise",
      "entityScope"                     => "ENTERPRISE",
      "lastUpdatedBy"                   => "43f8868f-4bc1-472c-9d19-533dcfcb1ee0",
      "lastUpdatedDate"                 => 1_507_237_665_000,
      "creationDate"                    => 1_507_220_277_000,
      "routeDistinguisher"              => "65534:56261",
      "routeTarget"                     => "65534:9065",
      "name"                            => "AWS_DEV01",
      "description"                     => "10.10.0.0/16",
      "maintenanceMode"                 => "DISABLED",
      "dhcpServerAddresses"             => nil,
      "underlayEnabled"                 => "DISABLED",
      "policyChangeStatus"              => nil,
      "backHaulRouteDistinguisher"      => "65534:2408",
      "backHaulRouteTarget"             => "65534:13947",
      "backHaulVNID"                    => 9_130_731,
      "advertiseCriteria"               => nil,
      "importRouteTarget"               => "65534:9065",
      "exportRouteTarget"               => "65534:9065",
      "encryption"                      => "DISABLED",
      "localAS"                         => nil,
      "owner"                           => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
      "ID"                              => "d0c3274c-397a-4173-8981-bfd2f99ef8c6",
      "parentID"                        => "6abac3ad-a05d-4b93-9556-4ba5010fb13b",
      "externalID"                      => nil,
      "serviceID"                       => 1_094_130_591,
      "customerID"                      => 87_886,
      "DHCPBehavior"                    => "CONSUME",
      "DHCPServerAddress"               => nil,
      "secondaryDHCPServerAddress"      => nil,
      "labelID"                         => 28_682,
      "multicast"                       => "DISABLED",
      "PATEnabled"                      => "DISABLED",
      "associatedPATMapperID"           => nil,
      "associatedMulticastChannelMapID" => nil,
      "stretched"                       => false,
      "tunnelType"                      => "VXLAN",
      "ECMPCount"                       => 1,
      "templateID"                      => "a6b21916-343e-4663-ae3d-949f744acc15",
      "enterpriseID"                    => "6abac3ad-a05d-4b93-9556-4ba5010fb13b",
      "uplinkPreference"                => "PRIMARY_SECONDARY",
      "globalRoutingEnabled"            => false,
      "leakingEnabled"                  => false,
      "DPI"                             => "DISABLED",
      "permittedAction"                 => nil,
      "associatedBGPProfileID"          => nil,
      "BGPEnabled"                      => false,
      "domainID"                        => 395_377,
      "domainVLANID"                    => 0
    )
  end

  def assert_zones_parameters(zones)
    expect(zones.count).to be(10)

    # test first zone object
    zone = zones.first

    expect(zone).to include(
      "children"                        => nil,
      "parentType"                      => "domain",
      "entityScope"                     => "ENTERPRISE",
      "lastUpdatedBy"                   => "d2dc3ac6-01a4-4755-8686-e0be7f36f088",
      "lastUpdatedDate"                 => 1_507_220_282_000,
      "creationDate"                    => 1_507_220_282_000,
      "address"                         => nil,
      "netmask"                         => nil,
      "name"                            => "AWS_DEV01-NSG Zone",
      "dynamicIpv6Address"              => nil,
      "description"                     => nil,
      "maintenanceMode"                 => "DISABLED",
      "publicZone"                      => false,
      "encryption"                      => "INHERITED",
      "owner"                           => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
      "ID"                              => "76ac549a-5843-4f1b-ac90-b21ff6edc2a4",
      "parentID"                        => "0a8d986a-4e17-440c-85b7-7827afb8a95f",
      "externalID"                      => nil,
      "IPv6Address"                     => nil,
      "IPType"                          => "IPV4",
      "numberOfHostsInSubnets"          => 0,
      "templateID"                      => nil,
      "policyGroupID"                   => 560_197_284,
      "multicast"                       => "INHERITED",
      "associatedMulticastChannelMapID" => nil,
      "DPI"                             => "INHERITED"
    )
  end

  def assert_subnets_parameters(subnets)
    expect(subnets.count).to be(10)

    # test first subnet object
    subnet = subnets.first

    expect(subnet).to include(
      "children"                          => nil,
      "parentType"                        => "zone",
      "entityScope"                       => "ENTERPRISE",
      "lastUpdatedBy"                     => "d2dc3ac6-01a4-4755-8686-e0be7f36f088",
      "lastUpdatedDate"                   => 1_507_220_286_000,
      "creationDate"                      => 1_507_220_282_000,
      "address"                           => "10.10.255.224",
      "netmask"                           => "255.255.255.240",
      "name"                              => "AWS_DEV01-NSG Access Subnet",
      "dynamicIpv6Address"                => true,
      "gateway"                           => "10.10.255.234",
      "description"                       => nil,
      "maintenanceMode"                   => "DISABLED",
      "routeDistinguisher"                => "65534:27628",
      "routeTarget"                       => "65534:21195",
      "vnId"                              => 15_015_226,
      "underlayEnabled"                   => "INHERITED",
      "underlay"                          => false,
      "entityState"                       => nil,
      "splitSubnet"                       => false,
      "encryption"                        => "INHERITED",
      "owner"                             => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
      "ID"                                => "4da803f7-c0d2-4beb-b02e-341ea77e377f",
      "parentID"                          => "76ac549a-5843-4f1b-ac90-b21ff6edc2a4",
      "externalID"                        => nil,
      "IPv6Address"                       => nil,
      "IPType"                            => "IPV4",
      "IPv6Gateway"                       => nil,
      "serviceID"                         => 642_198_274,
      "gatewayMACAddress"                 => "06:f0:4d:3f:6f:06",
      "PATEnabled"                        => "INHERITED",
      "policyGroupID"                     => 1_517_355_712,
      "public"                            => false,
      "templateID"                        => nil,
      "associatedSharedNetworkResourceID" => nil,
      "DHCPRelayStatus"                   => "DISABLED",
      "proxyARP"                          => false,
      "multicast"                         => "INHERITED",
      "associatedMulticastChannelMapID"   => nil,
      "DPI"                               => "INHERITED",
      "useGlobalMAC"                      => "DISABLED"
    )
  end

  def assert_vms_parameters(vms)
    expect(vms.count).to be(1)

    # test first vms object
    vm = vms.first

    expect(vm).to include(
      "children"           => nil,
      "parentType"         => nil,
      "entityScope"        => "GLOBAL",
      "lastUpdatedBy"      => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
      "lastUpdatedDate"    => 1_507_800_610_000,
      "creationDate"       => 1_507_800_610_000,
      "name"               => "TEST-VM",
      "interfaces"         => [{ "children"            => nil,
                                 "parentType"          => "vm",
                                 "entityScope"         => "GLOBAL",
                                 "lastUpdatedBy"       => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
                                 "lastUpdatedDate"     => 1_507_800_610_000,
                                 "creationDate"        => 1_507_800_610_000,
                                 "name"                => "TEST-VM-vm-interface-0",
                                 "multiNICVPortName"   => nil,
                                 "policyDecisionID"    => nil,
                                 "domainName"          => "PREM_DEV01",
                                 "zoneName"            => "PREM_DEV01_DB",
                                 "attachedNetworkType" => "SUBNET",
                                 "netmask"             => "255.255.255.0",
                                 "gateway"             => "172.16.2.1",
                                 "networkName"         => "PREM_DEV01_DBNET",
                                 "owner"               => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
                                 "ID"                  => "9e3d4a42-39d1-4692-9f0c-3cfd87f7bd4e",
                                 "parentID"            => "e6d90dec-a798-4b14-87bd-fdb58db371c4",
                                 "externalID"          => nil,
                                 "IPAddress"           => "172.16.2.232",
                                 "IPv6Address"         => nil,
                                 "MAC"                 => "00:11:22:33:44:55",
                                 "VMUUID"              => "cd8a9864-89fc-0000-8e4a-000ac976163c",
                                 "domainID"            => "6aa67f95-dc10-4ada-993b-4fe5c5ad74c8",
                                 "attachedNetworkID"   => "cd8a9864-89fc-483c-8e4a-f99ac976163c",
                                 "zoneID"              => "b64436d0-cab4-49fb-82b9-dc37648e433e",
                                 "VPortID"             => "0b6ecb92-34c6-4fe2-b0fa-83bffedff339",
                                 "tierID"              => nil,
                                 "IPv6Gateway"         => nil,
                                 "VPortName"           => "TEST-VM-vPort-0" },
                               { "children"            => nil,
                                 "parentType"          => "vm",
                                 "entityScope"         => "GLOBAL",
                                 "lastUpdatedBy"       => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
                                 "lastUpdatedDate"     => 1_507_800_988_000,
                                 "creationDate"        => 1_507_800_988_000,
                                 "name"                => "if-00-22-33-44-55-66",
                                 "multiNICVPortName"   => nil,
                                 "policyDecisionID"    => nil,
                                 "domainName"          => "PREM_DEV01",
                                 "zoneName"            => "PREM_DEV01_DB",
                                 "attachedNetworkType" => "SUBNET",
                                 "netmask"             => "255.255.255.0",
                                 "gateway"             => "172.16.2.1",
                                 "networkName"         => "PREM_DEV01_DBNET",
                                 "owner"               => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
                                 "ID"                  => "d7571ad1-a42d-4e9d-b9bf-28b5fa807cd8",
                                 "parentID"            => "e6d90dec-a798-4b14-87bd-fdb58db371c4",
                                 "externalID"          => nil,
                                 "IPAddress"           => "172.16.2.100",
                                 "IPv6Address"         => nil,
                                 "MAC"                 => "00:22:33:44:55:66",
                                 "VMUUID"              => "cd8a9864-89fc-0000-8e4a-000ac976163c",
                                 "domainID"            => "6aa67f95-dc10-4ada-993b-4fe5c5ad74c8",
                                 "attachedNetworkID"   => "cd8a9864-89fc-483c-8e4a-f99ac976163c",
                                 "zoneID"              => "b64436d0-cab4-49fb-82b9-dc37648e433e",
                                 "VPortID"             => "3ced0da1-25cf-4199-8f9f-f8f40c98ad40",
                                 "tierID"              => nil,
                                 "IPv6Gateway"         => nil,
                                 "VPortName"           => "3ced0da1-25cf-4199-8f9f-f8f40c98ad40" },
                               { "children"            => nil,
                                 "parentType"          => "vm",
                                 "entityScope"         => "GLOBAL",
                                 "lastUpdatedBy"       => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
                                 "lastUpdatedDate"     => 1_507_801_217_000,
                                 "creationDate"        => 1_507_801_217_000,
                                 "name"                => "if-00-33-44-55-66-77",
                                 "multiNICVPortName"   => nil,
                                 "policyDecisionID"    => nil,
                                 "domainName"          => "PREM_DEV01",
                                 "zoneName"            => "PREM_DEV01_DB",
                                 "attachedNetworkType" => "SUBNET",
                                 "netmask"             => "255.255.255.0",
                                 "gateway"             => "172.16.2.1",
                                 "networkName"         => "PREM_DEV01_DBNET",
                                 "owner"               => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
                                 "ID"                  => "fd3ec6c4-8889-4555-b331-85f4c1489087",
                                 "parentID"            => "e6d90dec-a798-4b14-87bd-fdb58db371c4",
                                 "externalID"          => nil,
                                 "IPAddress"           => "172.16.2.162",
                                 "IPv6Address"         => nil,
                                 "MAC"                 => "00:33:44:55:66:77",
                                 "VMUUID"              => "cd8a9864-89fc-0000-8e4a-000ac976163c",
                                 "domainID"            => "6aa67f95-dc10-4ada-993b-4fe5c5ad74c8",
                                 "attachedNetworkID"   => "cd8a9864-89fc-483c-8e4a-f99ac976163c",
                                 "zoneID"              => "b64436d0-cab4-49fb-82b9-dc37648e433e",
                                 "VPortID"             => "e0fd400b-8873-4da5-ba99-d49a390cd5de",
                                 "tierID"              => nil,
                                 "IPv6Gateway"         => nil,
                                 "VPortName"           => "e0fd400b-8873-4da5-ba99-d49a390cd5de" },
                               { "children"            => nil,
                                 "parentType"          => "vm",
                                 "entityScope"         => "GLOBAL",
                                 "lastUpdatedBy"       => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
                                 "lastUpdatedDate"     => 1_507_801_219_000,
                                 "creationDate"        => 1_507_801_219_000,
                                 "name"                => "if-00-33-44-55-66-88",
                                 "multiNICVPortName"   => nil,
                                 "policyDecisionID"    => nil,
                                 "domainName"          => nil,
                                 "zoneName"            => nil,
                                 "attachedNetworkType" => "L2DOMAIN",
                                 "netmask"             => "255.255.255.0",
                                 "gateway"             => "10.99.99.1",
                                 "networkName"         => "L2Base",
                                 "owner"               => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
                                 "ID"                  => "9240229c-1f82-4768-89e8-42d674addd94",
                                 "parentID"            => "e6d90dec-a798-4b14-87bd-fdb58db371c4",
                                 "externalID"          => nil,
                                 "IPAddress"           => "10.99.99.38",
                                 "IPv6Address"         => nil,
                                 "MAC"                 => "00:33:44:55:66:88",
                                 "VMUUID"              => "cd8a9864-89fc-0000-8e4a-000ac976163c",
                                 "domainID"            => nil,
                                 "attachedNetworkID"   => "03a955bc-add4-4346-abb5-85701477fa4e",
                                 "zoneID"              => nil,
                                 "VPortID"             => "fa30ee9f-5b67-435d-bc81-81cca34280cf",
                                 "tierID"              => nil,
                                 "IPv6Gateway"         => nil,
                                 "VPortName"           => "fa30ee9f-5b67-435d-bc81-81cca34280cf" },
                               { "children"            => nil,
                                 "parentType"          => "vm",
                                 "entityScope"         => "GLOBAL",
                                 "lastUpdatedBy"       => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
                                 "lastUpdatedDate"     => 1_507_801_220_000,
                                 "creationDate"        => 1_507_801_220_000,
                                 "name"                => "if-00-33-44-55-77-88",
                                 "multiNICVPortName"   => nil,
                                 "policyDecisionID"    => nil,
                                 "domainName"          => nil,
                                 "zoneName"            => nil,
                                 "attachedNetworkType" => "L2DOMAIN",
                                 "netmask"             => nil,
                                 "gateway"             => nil,
                                 "networkName"         => "L2Un",
                                 "owner"               => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
                                 "ID"                  => "04ae4fe7-16ab-4d78-abe1-3af8499a8e21",
                                 "parentID"            => "e6d90dec-a798-4b14-87bd-fdb58db371c4",
                                 "externalID"          => nil,
                                 "IPAddress"           => nil,
                                 "IPv6Address"         => nil,
                                 "MAC"                 => "00:33:44:55:77:88",
                                 "VMUUID"              => "cd8a9864-89fc-0000-8e4a-000ac976163c",
                                 "domainID"            => nil,
                                 "attachedNetworkID"   => "8efc78b0-df2a-4c6f-964b-463a9d106bed",
                                 "zoneID"              => nil,
                                 "VPortID"             => "d601ff9d-9604-4474-9d9d-5902bfc8df18",
                                 "tierID"              => nil,
                                 "IPv6Gateway"         => nil,
                                 "VPortName"           => "d601ff9d-9604-4474-9d9d-5902bfc8df18" }],
      "enterpriseName"     => "Development",
      "userName"           => "csproot",
      "deleteMode"         => nil,
      "deleteExpiry"       => 0,
      "computeProvisioned" => true,
      "resyncInfo"         => {
        "children"                => nil,
        "parentType"              => "vm",
        "entityScope"             => "GLOBAL",
        "lastUpdatedBy"           => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
        "lastUpdatedDate"         => 1_507_800_610_000,
        "creationDate"            => 1_507_800_610_000,
        "lastTimeResyncInitiated" => 0,
        "status"                  => "SUCCESS",
        "lastRequestTimestamp"    => 1_507_800_610_339,
        "owner"                   => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
        "ID"                      => "624911e0-7499-463d-8ec6-d1138bbb2a5a",
        "parentID"                => "e6d90dec-a798-4b14-87bd-fdb58db371c4",
        "externalID"              => nil
      },
      "owner"              => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
      "ID"                 => "e6d90dec-a798-4b14-87bd-fdb58db371c4",
      "parentID"           => nil,
      "externalID"         => nil,
      "UUID"               => "cd8a9864-89fc-0000-8e4a-000ac976163c",
      "status"             => "INIT",
      "reasonType"         => nil,
      "hypervisorIP"       => "FFFFFF",
      "siteIdentifier"     => nil,
      "enterpriseID"       => "6abac3ad-a05d-4b93-9556-4ba5010fb13b",
      "userID"             => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
      "domainIDs"          => ["6aa67f95-dc10-4ada-993b-4fe5c5ad74c8"],
      "l2DomainIDs"        => ["03a955bc-add4-4346-abb5-85701477fa4e",
                               "8efc78b0-df2a-4c6f-964b-463a9d106bed"],
      "zoneIDs"            => ["b64436d0-cab4-49fb-82b9-dc37648e433e"],
      "subnetIDs"          => ["cd8a9864-89fc-483c-8e4a-f99ac976163c"],
      "VRSID"              => nil,
      "orchestrationID"    => nil
    )
  end

  def assert_policy_groups_parameters(policy_groups)
    expect(policy_groups.count).to be(2)

    # test first policy_group object
    policy_group = policy_groups.first

    expect(policy_group).to include(
      "children"         => nil,
      "parentType"       => "domain",
      "entityScope"      => "ENTERPRISE",
      "lastUpdatedBy"    => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
      "lastUpdatedDate"  => 1_507_220_453_000,
      "creationDate"     => 1_507_220_453_000,
      "name"             => "DEV01_WORKLOAD",
      "description"      => nil,
      "type"             => "SOFTWARE",
      "external"         => false,
      "entityState"      => nil,
      "owner"            => "8a6f0e20-a4db-4878-ad84-9cc61756cd5e",
      "ID"               => "fadd09c4-9fea-46ec-8342-73f1b6a4df74",
      "parentID"         => "d0c3274c-397a-4173-8981-bfd2f99ef8c6",
      "externalID"       => nil,
      "EVPNCommunityTag" => nil,
      "templateID"       => nil,
      "policyGroupID"    => 2_081_390_816
    )
  end
end
