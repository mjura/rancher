package client

const (
	AKSStatusType              = "aksStatus"
	AKSStatusFieldUpstreamSpec = "upstreamSpec"
)

type AKSStatus struct {
	UpstreamSpec *AKSClusterConfigSpec `json:"upstreamSpec,omitempty" yaml:"upstreamSpec,omitempty"`
}
