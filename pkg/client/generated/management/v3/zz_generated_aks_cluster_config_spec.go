package client

const (
	AKSClusterConfigSpecType                             = "aksClusterConfigSpec"
	AKSClusterConfigSpecFieldAuthBaseURL                 = "authBaseUrl"
	AKSClusterConfigSpecFieldAzureCredentialSecret       = "azureCredentialSecret"
	AKSClusterConfigSpecFieldBaseURL                     = "baseUrl"
	AKSClusterConfigSpecFieldClusterName                 = "clusterName"
	AKSClusterConfigSpecFieldDNSPrefix                   = "masterDnsPrefix"
	AKSClusterConfigSpecFieldDisplayName                 = "displayName"
	AKSClusterConfigSpecFieldImported                    = "imported"
	AKSClusterConfigSpecFieldKubernetesVersion           = "kubernetesVersion"
	AKSClusterConfigSpecFieldLinuxAdminUsername          = "adminUsername"
	AKSClusterConfigSpecFieldLinuxSSHPublicKeyContents   = "sshPublicKeyContents"
	AKSClusterConfigSpecFieldLoadBalancerSku             = "loadBalancerSku"
	AKSClusterConfigSpecFieldNetworkDNSServiceIP         = "dnsServiceIp"
	AKSClusterConfigSpecFieldNetworkDockerBridgeCIDR     = "dockerBridgeCidr"
	AKSClusterConfigSpecFieldNetworkPlugin               = "networkPlugin"
	AKSClusterConfigSpecFieldNetworkPodCIDR              = "podCidr"
	AKSClusterConfigSpecFieldNetworkPolicy               = "networkPolicy"
	AKSClusterConfigSpecFieldNetworkServiceCIDR          = "serviceCidr"
	AKSClusterConfigSpecFieldNodeGroups                  = "nodeGroups"
	AKSClusterConfigSpecFieldPrivateAccess               = "privateAccess"
	AKSClusterConfigSpecFieldPublicAccess                = "publicAccess"
	AKSClusterConfigSpecFieldPublicAccessSources         = "publicAccessSources"
	AKSClusterConfigSpecFieldResourceGroup               = "resourceGroup"
	AKSClusterConfigSpecFieldResourceLocation            = "resourceLocation"
	AKSClusterConfigSpecFieldSubnet                      = "subnet"
	AKSClusterConfigSpecFieldSubscriptionID              = "subscriptionId"
	AKSClusterConfigSpecFieldTags                        = "tags"
	AKSClusterConfigSpecFieldTenantID                    = "tenantId"
	AKSClusterConfigSpecFieldVirtualNetwork              = "virtualNetwork"
	AKSClusterConfigSpecFieldVirtualNetworkResourceGroup = "virtualNetworkResourceGroup"
)

type AKSClusterConfigSpec struct {
	AuthBaseURL                 string            `json:"authBaseUrl,omitempty" yaml:"authBaseUrl,omitempty"`
	AzureCredentialSecret       string            `json:"azureCredentialSecret,omitempty" yaml:"azureCredentialSecret,omitempty"`
	BaseURL                     string            `json:"baseUrl,omitempty" yaml:"baseUrl,omitempty"`
	ClusterName                 string            `json:"clusterName,omitempty" yaml:"clusterName,omitempty"`
	DNSPrefix                   string            `json:"masterDnsPrefix,omitempty" yaml:"masterDnsPrefix,omitempty"`
	DisplayName                 string            `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	Imported                    bool              `json:"imported,omitempty" yaml:"imported,omitempty"`
	KubernetesVersion           string            `json:"kubernetesVersion,omitempty" yaml:"kubernetesVersion,omitempty"`
	LinuxAdminUsername          string            `json:"adminUsername,omitempty" yaml:"adminUsername,omitempty"`
	LinuxSSHPublicKeyContents   string            `json:"sshPublicKeyContents,omitempty" yaml:"sshPublicKeyContents,omitempty"`
	LoadBalancerSku             string            `json:"loadBalancerSku,omitempty" yaml:"loadBalancerSku,omitempty"`
	NetworkDNSServiceIP         string            `json:"dnsServiceIp,omitempty" yaml:"dnsServiceIp,omitempty"`
	NetworkDockerBridgeCIDR     string            `json:"dockerBridgeCidr,omitempty" yaml:"dockerBridgeCidr,omitempty"`
	NetworkPlugin               string            `json:"networkPlugin,omitempty" yaml:"networkPlugin,omitempty"`
	NetworkPodCIDR              string            `json:"podCidr,omitempty" yaml:"podCidr,omitempty"`
	NetworkPolicy               string            `json:"networkPolicy,omitempty" yaml:"networkPolicy,omitempty"`
	NetworkServiceCIDR          string            `json:"serviceCidr,omitempty" yaml:"serviceCidr,omitempty"`
	NodeGroups                  []NodeGroup       `json:"nodeGroups,omitempty" yaml:"nodeGroups,omitempty"`
	PrivateAccess               *bool             `json:"privateAccess,omitempty" yaml:"privateAccess,omitempty"`
	PublicAccess                *bool             `json:"publicAccess,omitempty" yaml:"publicAccess,omitempty"`
	PublicAccessSources         []string          `json:"publicAccessSources,omitempty" yaml:"publicAccessSources,omitempty"`
	ResourceGroup               string            `json:"resourceGroup,omitempty" yaml:"resourceGroup,omitempty"`
	ResourceLocation            string            `json:"resourceLocation,omitempty" yaml:"resourceLocation,omitempty"`
	Subnet                      string            `json:"subnet,omitempty" yaml:"subnet,omitempty"`
	SubscriptionID              string            `json:"subscriptionId,omitempty" yaml:"subscriptionId,omitempty"`
	Tags                        map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
	TenantID                    string            `json:"tenantId,omitempty" yaml:"tenantId,omitempty"`
	VirtualNetwork              string            `json:"virtualNetwork,omitempty" yaml:"virtualNetwork,omitempty"`
	VirtualNetworkResourceGroup string            `json:"virtualNetworkResourceGroup,omitempty" yaml:"virtualNetworkResourceGroup,omitempty"`
}
