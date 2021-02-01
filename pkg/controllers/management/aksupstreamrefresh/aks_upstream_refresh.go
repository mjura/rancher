package aksupstreamrefresh

import (
	"context"
	"github.com/Azure/go-autorest/autorest/to"
	"reflect"

	"github.com/rancher/aks-operator/controller"
	v1 "github.com/rancher/aks-operator/pkg/apis/aks.cattle.io/v1"
	apimgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	mgmtv3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/wrangler"
	wranglerv1 "github.com/rancher/wrangler/pkg/generated/controllers/core/v1"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	isAKSIndexer = "clusters.management.cattle.io/is-aks"
)

var (
	aksUpstreamRefresher *aksRefreshController
)

func init() {
	// possible settings controller, which references refresh
	// cron job, will run prior to StartaksUpstreamCronJob.
	// This ensure the CronJob will not be nil
	aksUpstreamRefresher = &aksRefreshController{
		refreshCronJob: cron.New(),
	}
}

type aksRefreshController struct {
	refreshCronJob *cron.Cron
	secretsCache   wranglerv1.SecretCache
	clusterClient  v3.ClusterClient
	clusterCache   v3.ClusterCache
}

func StartAKSUpstreamCronJob(wContext *wrangler.Context) {
	aksUpstreamRefresher.secretsCache = wContext.Core.Secret().Cache()
	aksUpstreamRefresher.clusterClient = wContext.Mgmt.Cluster()
	aksUpstreamRefresher.clusterCache = wContext.Mgmt.Cluster().Cache()

	aksUpstreamRefresher.clusterCache.AddIndexer(isAKSIndexer, func(obj *apimgmtv3.Cluster) ([]string, error) {
		if obj.Spec.AKSConfig == nil {
			return []string{}, nil
		}
		return []string{"true"}, nil
	})

	schedule, err := cron.ParseStandard(settings.AKSUpstreamRefreshCron.Get())
	if err != nil {
		logrus.Errorf("Error parsing AKS upstream cluster refresh cron. Upstream state will not be refreshed: %v", err)
		return
	}
	aksUpstreamRefresher.refreshCronJob.Schedule(schedule, cron.FuncJob(aksUpstreamRefresher.refreshAllUpstreamStates))
	aksUpstreamRefresher.refreshCronJob.Start()
}

func (e *aksRefreshController) refreshAllUpstreamStates() {
	logrus.Debugf("Refreshing AKS clusters' upstream states")
	clusters, err := e.clusterCache.GetByIndex(isAKSIndexer, "true")
	if err != nil {
		logrus.Error("error trying to refresh AKS clusters' upstream states")
		return
	}

	for _, cluster := range clusters {
		if _, err := e.refreshClusterUpstreamSpec(cluster); err != nil {
			logrus.Errorf("error refreshing AKS cluster [%s] upstream state", cluster.Name)
		}
	}
}

func (e *aksRefreshController) refreshClusterUpstreamSpec(cluster *mgmtv3.Cluster) (*mgmtv3.Cluster, error) {
	if cluster == nil || cluster.DeletionTimestamp != nil {
		return nil, nil
	}

	if cluster.Spec.AKSConfig == nil {
		return cluster, nil
	}

	logrus.Infof("checking cluster [%s] upstream state for changes", cluster.Name)

	if cluster.Status.AKSStatus.UpstreamSpec == nil {
		logrus.Infof("initial upstream spec for cluster [%s] has not been set by aks cluster handler yet, skipping", cluster.Name)
		return cluster, nil
	}

	upstreamSpec, err := GetComparableUpstreamSpec(e.secretsCache, cluster)
	if err != nil {
		return cluster, err
	}

	if !reflect.DeepEqual(cluster.Status.AKSStatus.UpstreamSpec, upstreamSpec) {
		logrus.Infof("updating cluster [%s], upstream change detected", cluster.Name)
		cluster = cluster.DeepCopy()
		cluster.Status.AKSStatus.UpstreamSpec = upstreamSpec
		cluster, err = e.clusterClient.Update(cluster)
		if err != nil {
			return cluster, err
		}
	}

	if !reflect.DeepEqual(cluster.Spec.AKSConfig, cluster.Status.AppliedSpec.AKSConfig) {
		logrus.Infof("cluster [%s] currently updating, skipping spec sync", cluster.Name)
		return cluster, nil
	}

	// check for changes between AKS spec on cluster and the AKS spec on the AKSClusterConfig object

	specMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(cluster.Spec.AKSConfig)
	if err != nil {
		return cluster, err
	}

	upstreamSpecMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(upstreamSpec)
	if err != nil {
		return cluster, err
	}

	var updateAKSConfig bool
	for key, value := range upstreamSpecMap {
		if specMap[key] == nil {
			continue
		}
		if reflect.DeepEqual(specMap[key], value) {
			continue
		}
		updateAKSConfig = true
		specMap[key] = value
	}

	if !updateAKSConfig {
		logrus.Infof("cluster [%s] matches upstream, skipping spec sync", cluster.Name)
		return cluster, nil
	}

	if err = runtime.DefaultUnstructuredConverter.FromUnstructured(specMap, cluster.Spec.AKSConfig); err != nil {
		return cluster, err
	}

	return e.clusterClient.Update(cluster)
}

func GetComparableUpstreamSpec(secretsCache wranglerv1.SecretCache, cluster *mgmtv3.Cluster) (*v1.AKSClusterConfigSpec, error) {
	ctx := context.Background()
	upstreamSpec, err := controller.BuildUpstreamClusterState(ctx, secretsCache, *cluster.Spec.AKSConfig)
	if err != nil {
		return nil, err
	}

	upstreamSpec.DisplayName = cluster.Spec.AKSConfig.DisplayName
	upstreamSpec.ClusterName = cluster.Spec.AKSConfig.ClusterName
	upstreamSpec.ResourceLocation = cluster.Spec.AKSConfig.ResourceLocation
	upstreamSpec.ResourceGroup = cluster.Spec.AKSConfig.ResourceGroup
	upstreamSpec.AzureCredentialSecret = cluster.Spec.AKSConfig.AzureCredentialSecret
	upstreamSpec.SubscriptionID = cluster.Spec.AKSConfig.SubscriptionID
	upstreamSpec.BaseURL = cluster.Spec.AKSConfig.BaseURL
	upstreamSpec.AuthBaseURL = cluster.Spec.AKSConfig.AuthBaseURL
	upstreamSpec.Imported = cluster.Spec.AKSConfig.Imported

	//BACADebug
	upstreamSpec.PublicAccess = to.BoolPtr(true)
	upstreamSpec.PrivateAccess = to.BoolPtr(false)

	//upstreamSpec.Subnets = cluster.Spec.AKSConfig.Subnets
	//upstreamSpec.SecurityGroups = cluster.Spec.AKSConfig.SecurityGroups
	//upstreamSpec.ServiceRole = cluster.Spec.AKSConfig.ServiceRole

	return upstreamSpec, nil
}
