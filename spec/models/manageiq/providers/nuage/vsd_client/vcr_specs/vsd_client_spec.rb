require 'date'
describe ManageIQ::Providers::Nuage::NetworkManager::VsdClient do
  include Vmdb::Logging

  UUID_REGEXP = /([0-9a-z]{8})-(([0-9a-z]{4})-){3}([0-9a-z]{12})/
  ROUTE_PROPERTY_REGEXP = /([0-9]{5}):([0-9a-z]{4,5})/
  IP_ADDR_REGEXP = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/
  MAC_ADDR_REGEXP = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/

  ENTERPRISE_ID = '6abac3ad-a05d-4b93-9556-4ba5010fb13b'
  DOMAIN_ID = 'd0c3274c-397a-4173-8981-bfd2f99ef8c6'
  ZONE_ID = '76ac549a-5843-4f1b-ac90-b21ff6edc2a4'
  SUBNET_ID = '4da803f7-c0d2-4beb-b02e-341ea77e377f'
  POLICY_GROUP_ID = 'fadd09c4-9fea-46ec-8342-73f1b6a4df74'

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

  context "when login successful" do
    before(:each) do
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/login', :record => :new_episodes) do
        @vsd_client = described_class.new("https://#{@hostname}:8443/nuage/api/v5_0", @userid, @password)
      end
    end

    it "should return valid non empty response for get_enterprises" do
      enterprises = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/enterprises', :record => :new_episodes) do
        enterprises = @vsd_client.get_enterprises
      end
      assert_object_not_empty(enterprises)
      assert_enterprises(enterprises)
    end

    it "should return valid non empty response for get_enterprise by id" do
      enterprise = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/enterprise', :record => :new_episodes) do
        enterprise = @vsd_client.get_enterprise(ENTERPRISE_ID)
      end
      assert_object_not_empty(enterprise)
      assert_enterprise(enterprise)
    end

    it "should return empty response for enterprises" do
      enterprises = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/enterprises_empty', :record => :new_episodes) do
        enterprises = @vsd_client.get_enterprises
      end
      expect(enterprises).to be_nil
    end

    it "should return empty response for get_enterprise by id" do
      enterprise = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/enterprise_empty', :record => :new_episodes) do
        enterprise = @vsd_client.get_enterprise(ENTERPRISE_ID)
      end
      expect(enterprise).to be_nil
    end

    it "should return valid non empty response for domains" do
      domains = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/domains', :record => :new_episodes) do
        domains = @vsd_client.get_domains
      end
      assert_object_not_empty(domains)
      assert_domains(domains)
    end

    it "should return valid non empty response for domain by id" do
      domain = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/domain', :record => :new_episodes) do
        domain = @vsd_client.get_domain(DOMAIN_ID)
      end
      assert_object_not_empty(domain)
      assert_domain(domain)
    end

    it "should return valid non empty response for domains for enterprise_id" do
      domains = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/domains_for_enterprise_id', :record => :new_episodes) do
        domains = @vsd_client.get_domains_for_enterprise(ENTERPRISE_ID)
      end
      assert_object_not_empty(domains)
      assert_domains(domains)
    end

    it "should return empty response for domains" do
      domains = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/domains_empty', :record => :new_episodes) do
        domains = @vsd_client.get_domains
      end

      expect(domains).to be_nil
    end

    it "should return empty response for domain by id" do
      domain = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/domain_empty', :record => :new_episodes) do
        domain = @vsd_client.get_domain(DOMAIN_ID)
      end
      expect(domain).to be_nil
    end

    it "should return empty response for domains for enterprise_id" do
      domains = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/domains_for_enterprise_id_empty', :record => :new_episodes) do
        domains = @vsd_client.get_domains_for_enterprise(ENTERPRISE_ID)
      end
      expect(domains).to be_nil
    end

    it "should return valid non empty response for zones" do
      zones = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/zones', :record => :new_episodes) do
        zones = @vsd_client.get_zones
      end
      assert_object_not_empty(zones)
      assert_zones(zones)
    end

    it "should return valid non empty response for zone by id" do
      zone = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/zone', :record => :new_episodes) do
        zone = @vsd_client.get_zone(ZONE_ID)
      end

      assert_object_not_empty(zone)
      assert_zone(zone)
    end

    it "should return empty response for zones" do
      zones = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/zones_empty', :record => :new_episodes) do
        zones = @vsd_client.get_zones
      end

      expect(zones).to be_nil
    end

    it "should return empty response for zone by id" do
      zone = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/zone_empty', :record => :new_episodes) do
        zone = @vsd_client.get_zone(ZONE_ID)
      end
      expect(zone).to be_nil
    end

    it "should return valid non empty response for subnets" do
      subnets = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/subnets', :record => :new_episodes) do
        subnets = @vsd_client.get_subnets
      end
      assert_object_not_empty(subnets)
      assert_subnets(subnets)
    end

    it "should return valid non empty response for subnet by id" do
      subnet = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/subnet', :record => :new_episodes) do
        subnet = @vsd_client.get_subnet(SUBNET_ID)
      end

      assert_object_not_empty(subnet)
      assert_subnet(subnet)
    end

    it "should return valid non empty response for subnets for domain" do
      subnets = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/subnets_for_domain', :record => :new_episodes) do
        subnets = @vsd_client.get_subnets_for_domain(DOMAIN_ID)
      end

      assert_object_not_empty(subnets)
      assert_subnets(subnets)
    end

    it "should return empty response for subnets" do
      subnets = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/subnets_empty', :record => :new_episodes) do
        subnets = @vsd_client.get_subnets
      end

      expect(subnets).to be_nil
    end

    it "should return empty response for subnet by id" do
      subnet = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/subnet_empty', :record => :new_episodes) do
        subnet = @vsd_client.get_subnet(SUBNET_ID)
      end
      expect(subnet).to be_nil
    end

    it "should return empty response for subnets for domain" do
      subnets = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/subnets_for_domain_empty', :record => :new_episodes) do
        subnets = @vsd_client.get_subnets_for_domain(DOMAIN_ID)
      end
      expect(subnets).to be_nil
    end

    it "should return valid non empty response for vms" do
      vms = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/vms', :record => :new_episodes) do
        vms = @vsd_client.get_vms
      end
      assert_object_not_empty(vms)
      assert_vms(vms)
    end

    it "should return empty response for vms" do
      vms = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/vms_empty', :record => :new_episodes) do
        vms = @vsd_client.get_vms
      end
      expect(vms).to be_nil
    end

    it "should return valid non empty response for policy_groups" do
      policy_groups = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/policy_groups', :record => :new_episodes) do
        policy_groups = @vsd_client.get_policy_groups
      end
      assert_object_not_empty(policy_groups)
      assert_policy_groups(policy_groups)
    end

    it "should return valid non empty response for policy_group by id" do
      policy_group = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/policy_group', :record => :new_episodes) do
        policy_group = @vsd_client.get_policy_group(POLICY_GROUP_ID)
      end

      assert_object_not_empty(policy_group)
      assert_policy_group(policy_group)
    end

    it "should return valid non empty response for policy_groups for domain" do
      policy_groups = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/policy_groups_for_domain', :record => :new_episodes) do
        policy_groups = @vsd_client.get_policy_groups_for_domain(DOMAIN_ID)
      end

      assert_object_not_empty(policy_groups)
      assert_policy_groups(policy_groups)
    end

    it "should return empty response for policy_groups" do
      policy_groups = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/policy_groups_empty', :record => :new_episodes) do
        policy_groups = @vsd_client.get_policy_groups
      end
      expect(policy_groups).to be_nil
    end

    it "should return empty response for policy_group by id" do
      policy_group = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/policy_group_empty', :record => :new_episodes) do
        policy_group = @vsd_client.get_policy_group(POLICY_GROUP_ID)
      end
      expect(policy_group).to be_nil
    end

    it "should return empty response for policy_groups for domain" do
      policy_groups = nil
      VCR.use_cassette(described_class.parent.name.underscore + '/vsd_client/policy_groups_for_domain_empty', :record => :new_episodes) do
        policy_groups = @vsd_client.get_policy_groups_for_domain(DOMAIN_ID)
      end
      expect(policy_groups).to be_nil
    end
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

  def assert_enterprises(enterprises)
    # test count
    expect(enterprises.count).to be > 0

    # test first enterprise object
    assert_enterprise(enterprises.first)
  end

  def assert_enterprise(enterprise)
    expect(enterprise).to include(
      "children",
      "parentType",
      "entityScope",
      "lastUpdatedBy",
      "lastUpdatedDate",
      "creationDate",
      "name",
      "description",
      "avatarType",
      "avatarData",
      "floatingIPsQuota",
      "floatingIPsUsed",
      "allowTrustedForwardingClass",
      "allowAdvancedQOSConfiguration",
      "allowedForwardingClasses",
      "allowGatewayManagement",
      "enableApplicationPerformanceManagement",
      "encryptionManagementMode",
      "localAS",
      "dictionaryVersion",
      "allowedForwardingMode",
      "owner",
      "ID",
      "parentID",
      "externalID",
      "customerID",
      "DHCPLeaseInterval",
      "enterpriseProfileID",
      "receiveMultiCastListID",
      "sendMultiCastListID",
      "associatedGroupKeyEncryptionProfileID",
      "associatedEnterpriseSecurityID",
      "associatedKeyServerMonitorID",
      "LDAPEnabled",
      "LDAPAuthorizationEnabled",
      "BGPEnabled",
    )

    # test for date values
    assert_datetime(enterprise['lastUpdatedDate'])
    assert_datetime(enterprise['creationDate'])

    # test for IDs
    assert_identifier_string(enterprise['ID'])
    assert_identifier_string(enterprise['lastUpdatedBy'])
    assert_identifier_string(enterprise['owner'])
    assert_identifier_string(enterprise['enterpriseProfileID'])
    assert_identifier_string(enterprise['receiveMultiCastListID'])
    assert_identifier_string(enterprise['associatedGroupKeyEncryptionProfileID'])
    assert_identifier_string(enterprise['associatedEnterpriseSecurityID'])
    assert_identifier_string(enterprise['associatedKeyServerMonitorID'])

    # test for regular string properties
    expect(enterprise['name']).to be_an(String)
    expect(enterprise['name'].length).to be > 0

    # test for regular integer properties
    expect(enterprise['floatingIPsQuota']).to be_an(Integer)
    expect(enterprise['floatingIPsUsed']).to be_an(Integer)
    expect(enterprise['dictionaryVersion']).to be_an(Integer)
    expect(enterprise['customerID']).to be_an(Integer)

    # test for boolean properties
    assert_boolean_property(enterprise['allowTrustedForwardingClass'])
    assert_boolean_property(enterprise['allowAdvancedQOSConfiguration'])
    assert_boolean_property(enterprise['allowGatewayManagement'])
    assert_boolean_property(enterprise['enableApplicationPerformanceManagement'])
    assert_boolean_property(enterprise['LDAPEnabled'])
    assert_boolean_property(enterprise['LDAPAuthorizationEnabled'])
    assert_boolean_property(enterprise['BGPEnabled'])

    # entity scope
    assert_entity_scope(enterprise['entityScope'])

    # enabled/disabled properties
    assert_enabled_disabled_inherited(enterprise['encryptionManagementMode'])
  end

  def assert_domains(domains)
    # test count
    expect(domains.count).to be > 0

    # test first domain object
    assert_domain(domains.first)
  end

  def assert_domain(domain)
    expect(domain).to include(
      "children",
      "parentType",
      "entityScope",
      "lastUpdatedBy",
      "lastUpdatedDate",
      "creationDate",
      "routeDistinguisher",
      "routeTarget",
      "name",
      "description",
      "maintenanceMode",
      "dhcpServerAddresses",
      "underlayEnabled",
      "policyChangeStatus",
      "backHaulRouteDistinguisher",
      "backHaulRouteTarget",
      "backHaulVNID",
      "advertiseCriteria",
      "importRouteTarget",
      "exportRouteTarget",
      "encryption",
      "localAS",
      "owner",
      "ID",
      "parentID",
      "externalID",
      "serviceID",
      "customerID",
      "DHCPBehavior",
      "DHCPServerAddress",
      "secondaryDHCPServerAddress",
      "labelID",
      "multicast",
      "PATEnabled",
      "associatedPATMapperID",
      "associatedMulticastChannelMapID",
      "stretched",
      "tunnelType",
      "ECMPCount",
      "templateID",
      "enterpriseID",
      "uplinkPreference",
      "globalRoutingEnabled",
      "leakingEnabled",
      "DPI",
      "permittedAction",
      "associatedBGPProfileID",
      "BGPEnabled",
      "domainID",
      "domainVLANID"
    )

    # test for date values
    assert_datetime(domain['lastUpdatedDate'])
    assert_datetime(domain['creationDate'])

    # test for IDs
    assert_identifier_string(domain['ID'])
    assert_identifier_string(domain['lastUpdatedBy'])
    assert_identifier_string(domain['owner'])
    assert_identifier_string(domain['parentID'])
    assert_identifier_string(domain['templateID'])
    assert_identifier_string(domain['enterpriseID'])

    # test for regular string properties
    expect(domain['parentType']).to be_an(String)
    expect(domain['parentType'].length).to be > 0
    expect(domain['name']).to be_an(String)
    expect(domain['name'].length).to be > 0
    expect(domain['description']).to be_an(String)
    expect(domain['description'].length).to be > 0

    # test for regular integer properties
    expect(domain['backHaulVNID']).to be_an(Integer)
    expect(domain['serviceID']).to be_an(Integer)
    expect(domain['customerID']).to be_an(Integer)
    expect(domain['labelID']).to be_an(Integer)
    expect(domain['ECMPCount']).to be_an(Integer)
    expect(domain['domainID']).to be_an(Integer)
    expect(domain['domainVLANID']).to be_an(Integer)

    # test for boolean properties
    assert_boolean_property(domain['stretched'])
    assert_boolean_property(domain['globalRoutingEnabled'])
    assert_boolean_property(domain['leakingEnabled'])
    assert_boolean_property(domain['BGPEnabled'])

    # test for entity scope
    assert_entity_scope(domain['entityScope'])

    # test for enabled/disabled properties
    assert_enabled_disabled_inherited(domain['maintenanceMode'])
    assert_enabled_disabled_inherited(domain['underlayEnabled'])
    assert_enabled_disabled_inherited(domain['encryption'])
    assert_enabled_disabled_inherited(domain['multicast'])
    assert_enabled_disabled_inherited(domain['PATEnabled'])
    assert_enabled_disabled_inherited(domain['DPI'])

    # test for route properties
    assert_route_property(domain['routeDistinguisher'])
    assert_route_property(domain['routeTarget'])
    assert_route_property(domain['backHaulRouteDistinguisher'])
    assert_route_property(domain['backHaulRouteTarget'])
    assert_route_property(domain['importRouteTarget'])
    assert_route_property(domain['exportRouteTarget'])
  end

  def assert_zones(zones)
    expect(zones.count).to be > 0

    # test first zone object
    assert_zone(zones.first)
  end

  def assert_zone(zone)
    expect(zone).to include(
      "children",
      "parentType",
      "entityScope",
      "lastUpdatedBy",
      "lastUpdatedDate",
      "creationDate",
      "address",
      "netmask",
      "name",
      "dynamicIpv6Address",
      "description",
      "maintenanceMode",
      "publicZone",
      "encryption",
      "owner",
      "ID",
      "parentID",
      "externalID",
      "IPv6Address",
      "IPType",
      "numberOfHostsInSubnets",
      "templateID",
      "policyGroupID",
      "multicast",
      "associatedMulticastChannelMapID",
      "DPI"
    )

    # test for date values
    assert_datetime(zone['lastUpdatedDate'])
    assert_datetime(zone['creationDate'])

    # test for IDs
    assert_identifier_string(zone['ID'])
    assert_identifier_string(zone['lastUpdatedBy'])
    assert_identifier_string(zone['owner'])
    assert_identifier_string(zone['parentID'])

    # test for regular string properties
    expect(zone['parentType']).to be_an(String)
    expect(zone['parentType'].length).to be > 0
    expect(zone['name']).to be_an(String)
    expect(zone['name'].length).to be > 0

    # test for regular integer properties
    expect(zone['numberOfHostsInSubnets']).to be_an(Integer)
    expect(zone['policyGroupID']).to be_an(Integer)

    # test for boolean properties
    assert_boolean_property(zone['publicZone'])

    # test for entity scope
    assert_entity_scope(zone['entityScope'])

    # test for enabled/disabled properties
    assert_enabled_disabled_inherited(zone['maintenanceMode'])
    assert_enabled_disabled_inherited(zone['encryption'])
    assert_enabled_disabled_inherited(zone['multicast'])
    assert_enabled_disabled_inherited(zone['DPI'])

    # test for IPType property
    assert_ip_type(zone['IPType'])
  end

  def assert_subnets(subnets)
    expect(subnets.count).to be > 0

    # test first subnet object
    assert_subnet(subnets.first)
  end

  def assert_subnet(subnet)
    expect(subnet).to include(
      "children",
      "parentType",
      "entityScope",
      "lastUpdatedBy",
      "lastUpdatedDate",
      "creationDate",
      "address",
      "netmask",
      "name",
      "dynamicIpv6Address",
      "gateway",
      "description",
      "maintenanceMode",
      "routeDistinguisher",
      "routeTarget",
      "vnId",
      "underlayEnabled",
      "underlay",
      "entityState",
      "splitSubnet",
      "encryption",
      "owner",
      "ID",
      "parentID",
      "externalID",
      "IPv6Address",
      "IPType",
      "IPv6Gateway",
      "serviceID",
      "gatewayMACAddress",
      "PATEnabled",
      "policyGroupID",
      "public",
      "templateID",
      "associatedSharedNetworkResourceID",
      "DHCPRelayStatus",
      "proxyARP",
      "multicast",
      "associatedMulticastChannelMapID",
      "DPI",
      "useGlobalMAC"
    )

    # test for date values
    assert_datetime(subnet['lastUpdatedDate'])
    assert_datetime(subnet['creationDate'])

    # test for IDs
    assert_identifier_string(subnet['ID'])
    assert_identifier_string(subnet['lastUpdatedBy'])
    assert_identifier_string(subnet['owner'])
    assert_identifier_string(subnet['parentID'])

    # test for regular string properties
    expect(subnet['parentType']).to be_an(String)
    expect(subnet['parentType'].length).to be > 0
    expect(subnet['name']).to be_an(String)
    expect(subnet['name'].length).to be > 0

    # test for regular integer properties
    expect(subnet['vnId']).to be_an(Integer)
    expect(subnet['serviceID']).to be_an(Integer)
    expect(subnet['policyGroupID']).to be_an(Integer)

    # test for boolean properties
    assert_boolean_property(subnet['underlay'])
    assert_boolean_property(subnet['splitSubnet'])
    assert_boolean_property(subnet['public'])
    assert_boolean_property(subnet['proxyARP'])

    # test for entity scope
    assert_entity_scope(subnet['entityScope'])

    # test for enabled/disabled properties
    assert_enabled_disabled_inherited(subnet['maintenanceMode'])
    assert_enabled_disabled_inherited(subnet['underlayEnabled'])
    assert_enabled_disabled_inherited(subnet['encryption'])
    assert_enabled_disabled_inherited(subnet['PATEnabled'])
    assert_enabled_disabled_inherited(subnet['DHCPRelayStatus'])
    assert_enabled_disabled_inherited(subnet['multicast'])
    assert_enabled_disabled_inherited(subnet['DPI'])
    assert_enabled_disabled_inherited(subnet['useGlobalMAC'])

    # test for IPType property
    assert_ip_type(subnet['IPType'])

    # test IP properties
    assert_ip(subnet['address'])
    assert_ip(subnet['netmask'])
    assert_ip(subnet['gateway'])

    # test for route properties
    assert_route_property(subnet['routeDistinguisher'])
    assert_route_property(subnet['routeTarget'])
  end

  def assert_vms(vms)
    expect(vms.count).to be > 0

    # test first vms object
    assert_vm(vms.first)
  end

  def assert_vm(vm)
    expect(vm).to include(
      "children",
      "parentType",
      "entityScope",
      "lastUpdatedBy",
      "lastUpdatedDate",
      "creationDate",
      "name",
      "interfaces",
      "enterpriseName",
      "userName",
      "deleteMode",
      "deleteExpiry",
      "computeProvisioned",
      "resyncInfo",
      "owner",
      "ID",
      "parentID",
      "externalID",
      "UUID",
      "status",
      "reasonType",
      "hypervisorIP",
      "siteIdentifier",
      "enterpriseID",
      "userID",
      "domainIDs",
      "l2DomainIDs",
      "zoneIDs",
      "subnetIDs",
      "VRSID",
      "orchestrationID"
    )

    # test for date values
    assert_datetime(vm['lastUpdatedDate'])
    assert_datetime(vm['creationDate'])

    # test for IDs
    assert_identifier_string(vm['ID'])
    assert_identifier_string(vm['lastUpdatedBy'])
    assert_identifier_string(vm['owner'])
    assert_identifier_string(vm['UUID'])
    assert_identifier_string(vm['enterpriseID'])
    assert_identifier_string(vm['userID'])

    assert_identifier_array(vm['domainIDs'])
    assert_identifier_array(vm['l2DomainIDs'])
    assert_identifier_array(vm['zoneIDs'])
    assert_identifier_array(vm['subnetIDs'])

    # test for regular string properties
    expect(vm['name']).to be_an(String)
    expect(vm['enterpriseName']).to be_an(String)
    expect(vm['userName']).to be_an(String)
    expect(vm['status']).to be_an(String)
    expect(vm['hypervisorIP']).to be_an(String)

    # test for regular integer properties
    expect(vm['deleteExpiry']).to be_an(Integer)

    # test for boolean properties
    assert_boolean_property(vm['computeProvisioned'])

    # test for entity scope
    assert_entity_scope(vm['entityScope'])

    # test for interfaces
    expect(vm['interfaces']).to be_a_kind_of(Array)
    assert_interface(vm['interfaces'].first)

    # test for resync info
    assert_resync_info(vm['resyncInfo'])
  end

  def assert_policy_groups(policy_groups)
    expect(policy_groups.count).to be > 0

    # test first policy_group object
    policy_group = policy_groups.first

    assert_policy_group(policy_group)
  end

  def assert_policy_group(policy_group)
    expect(policy_group).to include(
      "children",
      "parentType",
      "entityScope",
      "lastUpdatedBy",
      "lastUpdatedDate",
      "creationDate",
      "name",
      "description",
      "type",
      "external",
      "entityState",
      "owner",
      "ID",
      "parentID",
      "externalID",
      "EVPNCommunityTag",
      "templateID",
      "policyGroupID"
    )

    # test for date values
    assert_datetime(policy_group['lastUpdatedDate'])
    assert_datetime(policy_group['creationDate'])

    # test for IDs
    assert_identifier_string(policy_group['ID'])
    assert_identifier_string(policy_group['lastUpdatedBy'])
    assert_identifier_string(policy_group['owner'])
    assert_identifier_string(policy_group['parentID'])

    # test for regular string properties
    expect(policy_group['parentType']).to be_an(String)
    expect(policy_group['name']).to be_an(String)
    expect(policy_group['type']).to be_an(String)

    # test for regular integer properties
    expect(policy_group['policyGroupID']).to be_an(Integer)

    # test for boolean properties
    assert_boolean_property(policy_group['external'])

    # test for entity scope
    assert_entity_scope(policy_group['entityScope'])
  end

  def assert_identifier_string(identifier)
    expect(identifier =~ UUID_REGEXP).to be 0
  end

  def assert_route_property(route_property)
    expect(route_property =~ ROUTE_PROPERTY_REGEXP).to be 0
  end

  def assert_ip(ip_address)
    expect(ip_address =~ IP_ADDR_REGEXP).to be 0
  end

  def assert_mac_address(mac_address)
    expect(mac_address =~ MAC_ADDR_REGEXP).to be 0
  end

  def assert_boolean_property(boolean_property)
    expect(boolean_property).to be(!!boolean_property)
  end

  def assert_identifier_array(identifier_array)
    expect(identifier_array).to be_a_kind_of(Array)

    identifier_array.each do |id|
      assert_identifier_string(id)
    end
  end

  def assert_datetime(timestamp)
    expect(timestamp).to be_an(Integer)
    time = nil
    expect do
      time = Time.at(timestamp / 1000).utc
    end.to_not raise_error

    expect(time).to be < Time.now.utc
  end

  def assert_entity_scope(entity_scope)
    expect(entity_scope).to be_in(%w[ENTERPRISE GLOBAL])
  end

  def assert_enabled_disabled_inherited(enabled_disabled)
    expect(enabled_disabled).to be_in(%w[ENABLED DISABLED INHERITED])
  end

  def assert_ip_type(ip_type)
    expect(ip_type).to be_in(%w[IPV4 IPV6 DUALSTACK])
  end

  def assert_interface(interface)
    expect(interface).to include(
      "children",
      "parentType",
      "entityScope",
      "lastUpdatedBy",
      "lastUpdatedDate",
      "creationDate",
      "name",
      "multiNICVPortName",
      "policyDecisionID",
      "domainName",
      "zoneName",
      "attachedNetworkType",
      "netmask",
      "gateway",
      "networkName",
      "owner",
      "ID",
      "parentID",
      "externalID",
      "IPv6Address",
      "MAC",
      "VMUUID",
      "domainID",
      "attachedNetworkID",
      "zoneID",
      "VPortID",
      "tierID",
      "IPv6Gateway",
      "VPortName"
    )

    # test dates
    assert_datetime(interface['lastUpdatedDate'])
    assert_datetime(interface['creationDate'])

    # test identifiers
    assert_identifier_string(interface['ID'])
    assert_identifier_string(interface['lastUpdatedBy'])
    assert_identifier_string(interface['owner'])
    assert_identifier_string(interface['parentID'])
    assert_identifier_string(interface['VMUUID'])
    assert_identifier_string(interface['domainID'])
    assert_identifier_string(interface['attachedNetworkID'])
    assert_identifier_string(interface['zoneID'])
    assert_identifier_string(interface['VPortID'])

    # test strings
    expect(interface['parentType']).to be_an(String)
    expect(interface['name']).to be_an(String)
    expect(interface['domainName']).to be_an(String)
    expect(interface['zoneName']).to be_an(String)
    expect(interface['attachedNetworkType']).to be_an(String)
    expect(interface['networkName']).to be_an(String)
    expect(interface['VPortName']).to be_an(String)

    assert_ip(interface['netmask'])
    assert_ip(interface['gateway'])
    assert_ip(interface['IPAddress'])

    assert_mac_address(interface['MAC'])

    assert_entity_scope(interface['entityScope'])
  end

  def assert_resync_info(resync_info)
    expect(resync_info).to include(
      "children",
      "parentType",
      "entityScope",
      "lastUpdatedBy",
      "lastUpdatedDate",
      "creationDate",
      "lastTimeResyncInitiated",
      "status",
      "lastRequestTimestamp",
      "owner",
      "ID",
      "parentID",
      "externalID"
    )

    # test dates
    assert_datetime(resync_info['lastUpdatedDate'])
    assert_datetime(resync_info['creationDate'])
    assert_datetime(resync_info['lastRequestTimestamp'])

    # test identifiers
    assert_identifier_string(resync_info['ID'])
    assert_identifier_string(resync_info['lastUpdatedBy'])
    assert_identifier_string(resync_info['owner'])
    assert_identifier_string(resync_info['parentID'])

    # test strings
    expect(resync_info['parentType']).to be_an(String)
    expect(resync_info['status']).to be_an(String)

    # test for regular integer properties
    expect(resync_info['lastTimeResyncInitiated']).to be_an(Integer)

    assert_entity_scope(resync_info['entityScope'])
  end
end
