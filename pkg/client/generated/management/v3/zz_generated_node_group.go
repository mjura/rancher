package client

const (
	NodeGroupType                = "nodeGroup"
	NodeGroupFieldAvailableZones = "availableZones"
	NodeGroupFieldCount          = "count"
	NodeGroupFieldMaxPods        = "maxPods"
	NodeGroupFieldMode           = "mode"
	NodeGroupFieldName           = "name"
	NodeGroupFieldOsDiskSizeGB   = "osDiskSizeGB"
	NodeGroupFieldOsDiskType     = "osDiskType"
	NodeGroupFieldOsType         = "osType"
	NodeGroupFieldVMSize         = "vmSize"
	NodeGroupFieldVersion        = "version"
)

type NodeGroup struct {
	AvailableZones []string `json:"availableZones,omitempty" yaml:"availableZones,omitempty"`
	Count          int64    `json:"count,omitempty" yaml:"count,omitempty"`
	MaxPods        int64    `json:"maxPods,omitempty" yaml:"maxPods,omitempty"`
	Mode           string   `json:"mode,omitempty" yaml:"mode,omitempty"`
	Name           string   `json:"name,omitempty" yaml:"name,omitempty"`
	OsDiskSizeGB   int64    `json:"osDiskSizeGB,omitempty" yaml:"osDiskSizeGB,omitempty"`
	OsDiskType     string   `json:"osDiskType,omitempty" yaml:"osDiskType,omitempty"`
	OsType         string   `json:"osType,omitempty" yaml:"osType,omitempty"`
	VMSize         string   `json:"vmSize,omitempty" yaml:"vmSize,omitempty"`
	Version        string   `json:"version,omitempty" yaml:"version,omitempty"`
}
