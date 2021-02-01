package client

const (
	AKSStatusType                       = "aksStatus"
	AKSStatusFieldPrivateRequiresTunnel = "privateRequiresTunnel"
	AKSStatusFieldSecurityGroups        = "securityGroups"
	AKSStatusFieldSubnets               = "subnets"
	AKSStatusFieldUpstreamSpec          = "upstreamSpec"
	AKSStatusFieldVirtualNetwork        = "virtualNetwork"
)

type AKSStatus struct {
	PrivateRequiresTunnel *bool                 `json:"privateRequiresTunnel,omitempty" yaml:"privateRequiresTunnel,omitempty"`
	SecurityGroups        []string              `json:"securityGroups,omitempty" yaml:"securityGroups,omitempty"`
	Subnets               []string              `json:"subnets,omitempty" yaml:"subnets,omitempty"`
	UpstreamSpec          *AKSClusterConfigSpec `json:"upstreamSpec,omitempty" yaml:"upstreamSpec,omitempty"`
	VirtualNetwork        string                `json:"virtualNetwork,omitempty" yaml:"virtualNetwork,omitempty"`
}
