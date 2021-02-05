package aks

import (
	"context"
	"github.com/Azure/go-autorest/autorest/to"

	//"encoding/base64"
	stderrors "errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	//"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/rancher/aks-operator/controller"
	aksv1 "github.com/rancher/aks-operator/pkg/apis/aks.cattle.io/v1"
	"github.com/rancher/norman/condition"
	apimgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	apiprojv3 "github.com/rancher/rancher/pkg/apis/project.cattle.io/v3"
	utils2 "github.com/rancher/rancher/pkg/app"
	"github.com/rancher/rancher/pkg/catalog/manager"
	"github.com/rancher/rancher/pkg/controllers/management/aksupstreamrefresh"
	"github.com/rancher/rancher/pkg/controllers/management/rbac"
	"github.com/rancher/rancher/pkg/dialer"
	v3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	corev1 "github.com/rancher/rancher/pkg/generated/norman/core/v1"
	mgmtv3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	projectv3 "github.com/rancher/rancher/pkg/generated/norman/project.cattle.io/v3"
	"github.com/rancher/rancher/pkg/kontainer-engine/drivers/util"
	"github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/rancher/pkg/project"
	"github.com/rancher/rancher/pkg/ref"
	"github.com/rancher/rancher/pkg/systemaccount"
	"github.com/rancher/rancher/pkg/types/config"
	typesDialer "github.com/rancher/rancher/pkg/types/config/dialer"
	"github.com/rancher/rancher/pkg/wrangler"
	wranglerv1 "github.com/rancher/wrangler/pkg/generated/controllers/core/v1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	//clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	//"sigs.k8s.io/aws-iam-authenticator/pkg/token"
	"sigs.k8s.io/yaml"
)

const (
	systemNS            = "cattle-system"
	aksAPIGroup         = "aks.cattle.io"
	aksV1               = "aks.cattle.io/v1"
	aksOperatorTemplate = "system-library-rancher-aks-operator"
	aksOperator         = "rancher-aks-operator"
	localCluster        = "local"
	enqueueTime         = time.Second * 5
	importedAnno        = "aks.cattle.io/imported"
)

type aksOperatorValues struct {
	HTTPProxy  string `json:"httpProxy,omitempty"`
	HTTPSProxy string `json:"httpsProxy,omitempty"`
	NoProxy    string `json:"noProxy,omitempty"`
}

type aksOperatorController struct {
	clusterEnqueueAfter  func(name string, duration time.Duration)
	secretsCache         wranglerv1.SecretCache
	templateCache        v3.CatalogTemplateCache
	projectCache         v3.ProjectCache
	appLister            projectv3.AppLister
	appClient            projectv3.AppInterface
	nsClient             corev1.NamespaceInterface
	clusterClient        v3.ClusterClient
	catalogManager       manager.CatalogManager
	systemAccountManager *systemaccount.Manager
	dynamicClient        dynamic.NamespaceableResourceInterface
	clientDialer         typesDialer.Factory
}

func Register(ctx context.Context, wContext *wrangler.Context, mgmtCtx *config.ManagementContext) {
	aksClusterConfigResource := schema.GroupVersionResource{
		Group:    aksAPIGroup,
		Version:  "v1",
		Resource: "aksclusterconfigs",
	}

	aksCCDynamicClient := mgmtCtx.DynamicClient.Resource(aksClusterConfigResource)
	e := &aksOperatorController{
		clusterEnqueueAfter:  wContext.Mgmt.Cluster().EnqueueAfter,
		secretsCache:         wContext.Core.Secret().Cache(),
		templateCache:        wContext.Mgmt.CatalogTemplate().Cache(),
		projectCache:         wContext.Mgmt.Project().Cache(),
		appLister:            mgmtCtx.Project.Apps("").Controller().Lister(),
		appClient:            mgmtCtx.Project.Apps(""),
		nsClient:             mgmtCtx.Core.Namespaces(""),
		clusterClient:        wContext.Mgmt.Cluster(),
		catalogManager:       mgmtCtx.CatalogManager,
		systemAccountManager: systemaccount.NewManager(mgmtCtx),
		dynamicClient:        aksCCDynamicClient,
		clientDialer:         mgmtCtx.Dialer,
	}

	wContext.Mgmt.Cluster().OnChange(ctx, "aks-operator-controller", e.onClusterChange)
}

func (e *aksOperatorController) onClusterChange(key string, cluster *mgmtv3.Cluster) (*mgmtv3.Cluster, error) {
	if cluster == nil || cluster.DeletionTimestamp != nil {
		return cluster, nil
	}

	if cluster.Spec.AKSConfig == nil {
		return cluster, nil
	}

	/*
	// Temporrary disabled
	if err := e.deployAKSOperator(); err != nil {
		failedToDeployAKSOperatorErr := "failed to deploy aks-operator: %v"
		var conditionErr error
		if cluster.Spec.AKSConfig.Imported {
			cluster, conditionErr = e.setFalse(cluster, apimgmtv3.ClusterConditionPending, fmt.Sprintf(failedToDeployAKSOperatorErr, err))
			if conditionErr != nil {
				return cluster, conditionErr
			}
		} else {
			cluster, conditionErr = e.setFalse(cluster, apimgmtv3.ClusterConditionProvisioned, fmt.Sprintf(failedToDeployAKSOperatorErr, err))
			if conditionErr != nil {
				return cluster, conditionErr
			}
		}
		return cluster, err
	}
	*/

	fmt.Printf("[AKS] BACADebug cluster.Status.Driver \n")
	// set driver name
	if cluster.Status.Driver == "" {
		cluster = cluster.DeepCopy()
		cluster.Status.Driver = apimgmtv3.ClusterDriverAKS
		var err error
		cluster, err = e.clusterClient.Update(cluster)
		if err != nil {
			return cluster, err
		}
	}

	// get aks Cluster Config, if it does not exist, create it
	aksClusterConfigDynamic, err := e.dynamicClient.Namespace(namespace.GlobalNamespace).Get(context.TODO(), cluster.Name, v1.GetOptions{})
	fmt.Printf("[AKS] BACADebug aksClusterConfigDynamic err %v \n", err)
	if err != nil {
		if !errors.IsNotFound(err) {
			return cluster, err
		}

		cluster, err = e.setUnknown(cluster, apimgmtv3.ClusterConditionWaiting, "Waiting for API to be available")
		if err != nil {
			return cluster, err
		}

		aksClusterConfigDynamic, err = buildAKSCCCreateObject(cluster)
		if err != nil {
			return cluster, err
		}

		aksClusterConfigDynamic, err = e.dynamicClient.Namespace(namespace.GlobalNamespace).Create(context.TODO(), aksClusterConfigDynamic, v1.CreateOptions{})
		if err != nil {
			return cluster, err
		}

	}

	aksClusterConfigMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&cluster.Spec.AKSConfig)
	if err != nil {
		return cluster, err
	}

	// check for changes between aks spec on cluster and the aks spec on the aksClusterConfig object
	if !reflect.DeepEqual(aksClusterConfigMap, aksClusterConfigDynamic.Object["spec"]) {
		logrus.Infof("change detected for cluster [%s], updating AKSClusterConfig", cluster.Name)
		return e.updateAKSClusterConfig(cluster, aksClusterConfigDynamic, aksClusterConfigMap)
	}

	// get aks Cluster Config's phase
	status, _ := aksClusterConfigDynamic.Object["status"].(map[string]interface{})
	phase, _ := status["phase"]
	failureMessage, _ := status["failureMessage"].(string)
	if strings.Contains(failureMessage, "403") {
		failureMessage = fmt.Sprintf("cannot access aks, check cloud credential: %s", failureMessage)
	}
	fmt.Printf("[AKS] BACADebug switch phase \n")
	switch phase {
	case "creating":
		// set provisioning to unknown
		cluster, err = e.setUnknown(cluster, apimgmtv3.ClusterConditionProvisioned, "")
		if err != nil {
			return cluster, err
		}

		if cluster.Status.AKSStatus.UpstreamSpec == nil {
			cluster, err = e.setInitialUpstreamSpec(cluster)
			if err != nil {
				return cluster, err
				//if !notFound(err) {
				//	return cluster, err
				//}
			}
			return cluster, nil
		}

		e.clusterEnqueueAfter(cluster.Name, enqueueTime)
		if failureMessage == "" {
			logrus.Infof("waiting for cluster AKS [%s] to finish creating", cluster.Name)
			return e.setUnknown(cluster, apimgmtv3.ClusterConditionProvisioned, "")
		}
		logrus.Infof("waiting for cluster AKS [%s] create failure to be resolved", cluster.Name)
		return e.setFalse(cluster, apimgmtv3.ClusterConditionProvisioned, failureMessage)
	case "active":
		fmt.Printf("[AKS] BACADebug step 1 \n")
		if cluster.Status.AKSStatus.UpstreamSpec == nil {
			// non imported clusters will have already had upstream spec set
			return e.setInitialUpstreamSpec(cluster)
		}

		if apimgmtv3.ClusterConditionPending.IsUnknown(cluster) {
			cluster = cluster.DeepCopy()
			apimgmtv3.ClusterConditionPending.True(cluster)
			cluster, err = e.clusterClient.Update(cluster)
			if err != nil {
				return cluster, err
			}
		}
		fmt.Printf("[AKS] BACADebug step 1 end \n")

		if cluster.Spec.AKSConfig.Imported {
			if cluster.Status.AKSStatus.UpstreamSpec == nil {
				// non imported clusters will have already had upstream spec set
				return e.setInitialUpstreamSpec(cluster)
			}

			if apimgmtv3.ClusterConditionPending.IsUnknown(cluster) {
				cluster = cluster.DeepCopy()
				apimgmtv3.ClusterConditionPending.True(cluster)
				cluster, err = e.clusterClient.Update(cluster)
				if err != nil {
					return cluster, err
				}
			}
		}
		fmt.Printf("[AKS] BACADebug step 2 \n")
		/*
		addNgMessage := "Cannot deploy agent without nodegroups. Add a nodegroup."
		noNodeGroupsOnSpec := len(cluster.Spec.AKSConfig.NodeGroups) == 0
		noNodeGroupsOnUpstreamSpec := len(cluster.Status.AKSStatus.UpstreamSpec.NodeGroups) == 0
		if (cluster.Spec.AKSConfig.NodeGroups != nil && noNodeGroupsOnSpec) || (cluster.Spec.AKSConfig.NodeGroups == nil && noNodeGroupsOnUpstreamSpec) {
			cluster, err = e.setFalse(cluster, apimgmtv3.ClusterConditionWaiting, addNgMessage)
			if err != nil {
				return cluster, err
			}
		} else {
			if apimgmtv3.ClusterConditionWaiting.GetMessage(cluster) == addNgMessage {
				cluster = cluster.DeepCopy()
				apimgmtv3.ClusterConditionWaiting.Message(cluster, "Waiting for API to be available")
				cluster, err = e.clusterClient.Update(cluster)
				if err != nil {
					return cluster, err
				}
			}
		}
		*/
		fmt.Printf("[AKS] BACADebug step 3 \n")
		cluster, err = e.setTrue(cluster, apimgmtv3.ClusterConditionProvisioned, "")
		if err != nil {
			return cluster, err
		}

		// If there are no subnets it can be assumed that networking fields are not provided. In which case they
		// should be created by the aks-operator, and needs to be copied to the cluster object.
		if len(cluster.Status.AKSStatus.Subnets) == 0 {
			subnets, _ := status["subnets"].([]interface{})
			if len(subnets) != 0 {
				// network field have been generated and are ready to be copied
				virtualNetwork, _ := status["virtualNetwork"].(string)
				subnets, _ := status["subnets"].([]interface{})
				securityGroups, _ := status["securityGroups"].([]interface{})
				cluster = cluster.DeepCopy()

				// change fields on status to not be generated
				cluster.Status.AKSStatus.VirtualNetwork = virtualNetwork
				for _, val := range subnets {
					cluster.Status.AKSStatus.Subnets = append(cluster.Status.AKSStatus.Subnets, val.(string))
				}
				for _, val := range securityGroups {
					cluster.Status.AKSStatus.SecurityGroups = append(cluster.Status.AKSStatus.SecurityGroups, val.(string))
				}
				cluster, err = e.clusterClient.Update(cluster)
				if err != nil {
					return cluster, err
				}
			}
		}
		fmt.Printf("[AKS] BACADebug step 4 \n")
		/*
		if cluster.Status.APIEndpoint == "" {
			return e.recordCAAndAPIEndpoint(cluster)
		}
		*/

		fmt.Printf("[AKS] BACADebug cluster.Status.AKSStatus.PrivateRequiresTunnel %v PublicAccess %v \n", cluster.Status.AKSStatus.PrivateRequiresTunnel, cluster.Status.AKSStatus.UpstreamSpec.PublicAccess)

		/*
		if cluster.Status.AKSStatus.PrivateRequiresTunnel == nil && !*cluster.Status.AKSStatus.UpstreamSpec.PublicAccess {
			// Check to see if we can still use the public API endpoint even though
			// the cluster has private-only access
			serviceToken, mustTunnel, err := e.generateSATokenWithPublicAPI(cluster)
			if mustTunnel != nil {
				cluster = cluster.DeepCopy()
				cluster.Status.AKSStatus.PrivateRequiresTunnel = mustTunnel
				cluster.Status.ServiceAccountToken = serviceToken
				return e.clusterClient.Update(cluster)
			}
			if err != nil {
				return cluster, err
			}
		}
		*/
		fmt.Printf("[AKS] BACADebug cluster.Status.ServiceAccountToken %v \n", cluster.Status.ServiceAccountToken)
		if cluster.Status.ServiceAccountToken == "" {
			fmt.Printf("[AKS] BACADebug step 5 generateAndSetServiceAccount \n")
			cluster, err = e.generateAndSetServiceAccount(cluster)
			if err != nil {
				var statusErr error
				if strings.Contains(err.Error(), fmt.Sprintf(dialer.WaitForAgentError, cluster.Name)) {
					// In this case, the API endpoint is private and rancher is waiting for the import cluster command to be run.
					cluster, statusErr = e.setUnknown(cluster, apimgmtv3.ClusterConditionWaiting, "waiting for cluster agent to be deployed")
					if statusErr == nil {
						e.clusterEnqueueAfter(cluster.Name, enqueueTime)
					}
					return cluster, statusErr
				}
				cluster, statusErr = e.setFalse(cluster, apimgmtv3.ClusterConditionWaiting,
					fmt.Sprintf("failed to communicate with cluster: %v", err))
				if statusErr != nil {
					return cluster, statusErr
				}
				return cluster, err
			}
		}

		cluster, err = e.recordAppliedSpec(cluster)
		if err != nil {
			return cluster, err
		}

		return e.setTrue(cluster, apimgmtv3.ClusterConditionUpdated, "")
	case "updating":
		cluster, err = e.setTrue(cluster, apimgmtv3.ClusterConditionProvisioned, "")
		if err != nil {
			return cluster, err
		}

		e.clusterEnqueueAfter(cluster.Name, enqueueTime)
		if failureMessage == "" {
			logrus.Infof("waiting for cluster AKS [%s] to update", cluster.Name)
			return e.setUnknown(cluster, apimgmtv3.ClusterConditionUpdated, "")
		}
		logrus.Infof("waiting for cluster AKS [%s] update failure to be resolved", cluster.Name)
		return e.setFalse(cluster, apimgmtv3.ClusterConditionUpdated, failureMessage)
	default:
		if cluster.Spec.AKSConfig.Imported {
			cluster, err = e.setUnknown(cluster, apimgmtv3.ClusterConditionPending, "")
			if err != nil {
				return cluster, err
			}
			logrus.Infof("waiting for cluster import [%s] to start", cluster.Name)
		} else {
			logrus.Infof("waiting for cluster create [%s] to start", cluster.Name)
		}

		e.clusterEnqueueAfter(cluster.Name, enqueueTime)
		if failureMessage == "" {
			if cluster.Spec.AKSConfig.Imported {
				cluster, err = e.setUnknown(cluster, apimgmtv3.ClusterConditionPending, "")
				if err != nil {
					return cluster, err
				}
				logrus.Infof("waiting for cluster import [%s] to start", cluster.Name)
			} else {
				logrus.Infof("waiting for cluster create [%s] to start", cluster.Name)
			}
			return e.setUnknown(cluster, apimgmtv3.ClusterConditionProvisioned, "")
		}
		logrus.Infof("waiting for cluster AKS [%s] pre-create failure to be resolved", cluster.Name)
		return e.setFalse(cluster, apimgmtv3.ClusterConditionProvisioned, failureMessage)
	}
}

func (e *aksOperatorController) setInitialUpstreamSpec(cluster *mgmtv3.Cluster) (*mgmtv3.Cluster, error) {
	logrus.Infof("setting initial upstreamSpec on cluster [%s]", cluster.Name)
	cluster = cluster.DeepCopy()
	upstreamSpec, err := aksupstreamrefresh.GetComparableUpstreamSpec(e.secretsCache, cluster)
	if err != nil {
		return cluster, err
	}
	cluster.Status.AKSStatus.UpstreamSpec = upstreamSpec
	return e.clusterClient.Update(cluster)
}

// updateAKSClusterConfig updates the AKSClusterConfig object's spec with the cluster's AKSConfig if they are not equal..
func (e *aksOperatorController) updateAKSClusterConfig(cluster *mgmtv3.Cluster, aksClusterConfigDynamic *unstructured.Unstructured, spec map[string]interface{}) (*mgmtv3.Cluster, error) {
	list, err := e.dynamicClient.Namespace(namespace.GlobalNamespace).List(context.TODO(), v1.ListOptions{})
	if err != nil {
		return cluster, err
	}
	selector := fields.OneTermEqualSelector("metadata.name", cluster.Name)
	w, err := e.dynamicClient.Namespace(namespace.GlobalNamespace).Watch(context.TODO(), v1.ListOptions{ResourceVersion: list.GetResourceVersion(), FieldSelector: selector.String()})
	if err != nil {
		return cluster, err
	}
	aksClusterConfigDynamic.Object["spec"] = spec
	aksClusterConfigDynamic, err = e.dynamicClient.Namespace(namespace.GlobalNamespace).Update(context.TODO(), aksClusterConfigDynamic, v1.UpdateOptions{})
	if err != nil {
		return cluster, err
	}

	// AKS cluster and node group statuses are not always immediately updated. This cause the AKSConfig to
	// stay in "active" for a few seconds, causing the cluster to go back to "active".
	timeout := time.NewTimer(10 * time.Second)
	for {
		select {
		case event := <-w.ResultChan():
			aksClusterConfigDynamic = event.Object.(*unstructured.Unstructured)
			status, _ := aksClusterConfigDynamic.Object["status"].(map[string]interface{})
			if status["phase"] == "active" {
				continue
			}

			// this enqueue is necessary to ensure that the controller is reentered with the updating phase
			e.clusterEnqueueAfter(cluster.Name, enqueueTime)
			return e.setUnknown(cluster, apimgmtv3.ClusterConditionUpdated, "")
		case <-timeout.C:
			cluster, err = e.recordAppliedSpec(cluster)
			if err != nil {
				return cluster, err
			}
			return cluster, nil
		}
	}
}

// recordCAAndAPIEndpoint reads the AKSClusterConfig's secret once available. The CA cert and API endpoint are then copied to the cluster status.
func (e *aksOperatorController) recordCAAndAPIEndpoint(cluster *mgmtv3.Cluster) (*mgmtv3.Cluster, error) {
	backoff := wait.Backoff{
		Duration: 2 * time.Second,
		Factor:   2,
		Jitter:   0,
		Steps:    6,
		Cap:      20 * time.Second,
	}

	var caSecret *corev1.Secret
	err := wait.ExponentialBackoff(backoff, func() (bool, error) {
		var err error
		caSecret, err = e.secretsCache.Get(namespace.GlobalNamespace, cluster.Name)
		if err != nil {
			if !errors.IsNotFound(err) {
				return false, err
			}
			logrus.Infof("waiting for cluster [%s] data needed to generate service account token", cluster.Name)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return cluster, fmt.Errorf("failed waiting for cluster [%s] secret: %s", cluster.Name, err)
	}

	apiEndpoint := string(caSecret.Data["endpoint"])
	caCert := string(caSecret.Data["ca"])
	if cluster.Status.APIEndpoint == apiEndpoint && cluster.Status.CACert == caCert {
		return cluster, nil
	}

	var currentCluster *mgmtv3.Cluster
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		currentCluster, err = e.clusterClient.Get(cluster.Name, v1.GetOptions{})
		if err != nil {
			return err
		}
		currentCluster.Status.APIEndpoint = apiEndpoint
		currentCluster.Status.CACert = caCert
		currentCluster, err = e.clusterClient.Update(currentCluster)
		return err
	})

	return currentCluster, err
}

// generateAndSetServiceAccount uses the API endpoint and CA cert to generate a service account token. The token is then copied to the cluster status.
func (e *aksOperatorController) generateAndSetServiceAccount(cluster *mgmtv3.Cluster) (*mgmtv3.Cluster, error) {

	restConfig, err := e.getKubeConfig(cluster)
	if err != nil {
		return cluster, err
	}
	saToken, err := generateSAToken(restConfig)
	if err != nil {
		return cluster, err
	}

	cluster = cluster.DeepCopy()
	cluster.Status.ServiceAccountToken = saToken
	return e.clusterClient.Update(cluster)
}

// buildAKSCCCreateObject returns an object that can be used with the kubernetes dynamic client to
// create an AKSClusterConfig that matches the spec contained in the cluster's AKSConfig.
func buildAKSCCCreateObject(cluster *mgmtv3.Cluster) (*unstructured.Unstructured, error) {
	aksClusterConfig := aksv1.AKSClusterConfig{
		TypeMeta: v1.TypeMeta{
			Kind:       "AKSClusterConfig",
			APIVersion: aksV1,
		},
		ObjectMeta: v1.ObjectMeta{
			Name: cluster.Name,
			OwnerReferences: []v1.OwnerReference{
				{
					Kind:       cluster.Kind,
					APIVersion: rbac.RancherManagementAPIVersion,
					Name:       cluster.Name,
					UID:        cluster.UID,
				},
			},
		},
		Spec: *cluster.Spec.AKSConfig,
	}

	// convert AKS cluster config into unstructured object so it can be used with dynamic client
	aksClusterConfigMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&aksClusterConfig)
	if err != nil {
		return nil, err
	}

	return &unstructured.Unstructured{
		Object: aksClusterConfigMap,
	}, nil
}

// recordAppliedSpec sets the cluster's current spec as its appliedSpec
func (e *aksOperatorController) recordAppliedSpec(cluster *mgmtv3.Cluster) (*mgmtv3.Cluster, error) {
	if reflect.DeepEqual(cluster.Status.AppliedSpec.AKSConfig, cluster.Spec.AKSConfig) {
		return cluster, nil
	}

	cluster = cluster.DeepCopy()
	cluster.Status.AppliedSpec.AKSConfig = cluster.Spec.AKSConfig
	return e.clusterClient.Update(cluster)
}

// deployAKSOperator looks for the rancher-aks-operator app in the cattle-system namespace, if not found it is deployed.
// If it is found but is outdated, the latest version is installed.
func (e *aksOperatorController) deployAKSOperator() error {
	template, err := e.templateCache.Get(namespace.GlobalNamespace, aksOperatorTemplate)
	if err != nil {
		return err
	}

	latestTemplateVersion, err := e.catalogManager.LatestAvailableTemplateVersion(template, "local")
	if err != nil {
		return err
	}

	latestVersionID := latestTemplateVersion.ExternalID

	systemProject, err := project.GetSystemProject(localCluster, e.projectCache)
	if err != nil {
		return err
	}

	systemProjectID := ref.Ref(systemProject)
	_, systemProjectName := ref.Parse(systemProjectID)

	valuesYaml, err := generateValuesYaml()
	if err != nil {
		return err
	}

	app, err := e.appLister.Get(systemProjectName, aksOperator)
	if err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		logrus.Info("deploying AKS operator into local cluster's system project")
		creator, err := e.systemAccountManager.GetSystemUser(localCluster)
		if err != nil {
			return err
		}

		appProjectName, err := utils2.EnsureAppProjectName(e.nsClient, systemProjectName, localCluster, systemNS, creator.Name)
		if err != nil {
			return err
		}

		desiredApp := &apiprojv3.App{
			ObjectMeta: v1.ObjectMeta{
				Name:      aksOperator,
				Namespace: systemProjectName,
				Annotations: map[string]string{
					rbac.CreatorIDAnn: creator.Name,
				},
			},
			Spec: apiprojv3.AppSpec{
				Description:     "Operator for provisioning AKS clusters",
				ExternalID:      latestVersionID,
				ProjectName:     appProjectName,
				TargetNamespace: systemNS,
			},
		}

		desiredApp.Spec.ValuesYaml = valuesYaml

		// k3s upgrader doesn't exist yet, so it will need to be created
		if _, err = e.appClient.Create(desiredApp); err != nil {
			return err
		}
	} else {
		if app.Spec.ExternalID == latestVersionID && app.Spec.ValuesYaml == valuesYaml {
			// app is up to date, no action needed
			return nil
		}
		logrus.Info("updating AKS operator in local cluster's system project")
		desiredApp := app.DeepCopy()
		desiredApp.Spec.ExternalID = latestVersionID
		desiredApp.Spec.ValuesYaml = valuesYaml
		// new version of k3s upgrade available, update app
		if _, err = e.appClient.Update(desiredApp); err != nil {
			return err
		}
	}

	return nil
}

func (e *aksOperatorController) generateSATokenWithPublicAPI(cluster *mgmtv3.Cluster) (string, *bool, error) {
	var publicAccess *bool

	restConfig, err := e.getKubeConfig(cluster)
	serviceToken, err := generateSAToken(restConfig)
	if err != nil {
		var dnsError *net.DNSError
		if stderrors.As(err, &dnsError) && !dnsError.IsTemporary {
			return "", to.BoolPtr(true), nil
		}
	} else {
		publicAccess = to.BoolPtr(false)
	}

	return serviceToken, publicAccess, err
}

func generateSAToken(restConfig *rest.Config) (string, error) {
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return "", fmt.Errorf("error creating clientset: %v", err)
	}

	return util.GenerateServiceAccountToken(clientset)
}

func (e *aksOperatorController) getKubeConfig(cluster *mgmtv3.Cluster) (*rest.Config, error) {
	ctx := context.Background()
	restConfig, err := controller.GetClusterKubeconfig(ctx, e.secretsCache, *cluster.Spec.AKSConfig)
	if err != nil {
		return nil, err
	}
	return restConfig, nil
}

func (e *aksOperatorController) setUnknown(cluster *mgmtv3.Cluster, condition condition.Cond, message string) (*mgmtv3.Cluster, error) {
	if condition.IsUnknown(cluster) && condition.GetMessage(cluster) == message {
		return cluster, nil
	}
	cluster = cluster.DeepCopy()
	condition.Unknown(cluster)
	condition.Message(cluster, message)
	var err error
	cluster, err = e.clusterClient.Update(cluster)
	if err != nil {
		return cluster, fmt.Errorf("failed setting cluster [%s] condition %s unknown with message: %s", cluster.Name, condition, message)
	}
	return cluster, nil
}

func (e *aksOperatorController) setTrue(cluster *mgmtv3.Cluster, condition condition.Cond, message string) (*mgmtv3.Cluster, error) {
	if condition.IsTrue(cluster) && condition.GetMessage(cluster) == message {
		return cluster, nil
	}
	cluster = cluster.DeepCopy()
	condition.True(cluster)
	condition.Message(cluster, message)
	var err error
	cluster, err = e.clusterClient.Update(cluster)
	if err != nil {
		return cluster, fmt.Errorf("failed setting cluster [%s] condition %s true with message: %s", cluster.Name, condition, message)
	}
	return cluster, nil
}

func (e *aksOperatorController) setFalse(cluster *mgmtv3.Cluster, condition condition.Cond, message string) (*mgmtv3.Cluster, error) {
	if condition.IsFalse(cluster) && condition.GetMessage(cluster) == message {
		return cluster, nil
	}
	cluster = cluster.DeepCopy()
	condition.False(cluster)
	condition.Message(cluster, message)
	var err error
	cluster, err = e.clusterClient.Update(cluster)
	if err != nil {
		return cluster, fmt.Errorf("failed setting cluster [%s] condition %s false with message: %s", cluster.Name, condition, message)
	}
	return cluster, nil
}

//func notFound(err error) bool {
//	if awsErr, ok := err.(awserr.Error); ok {
//		return awsErr.Code() == aks.ErrCodeResourceNotFoundException
//	}
//	return false
//}

// generateValuesYaml generates a YAML string containing any
// necessary values to override defaults in values.yaml. If
// no defaults need to be overwritten, an empty string will
// be returned.
func generateValuesYaml() (string, error) {
	values := aksOperatorValues{
		HTTPProxy:  os.Getenv("HTTP_PROXY"),
		HTTPSProxy: os.Getenv("HTTPS_PROXY"),
		NoProxy:    os.Getenv("NO_PROXY"),
	}

	valuesYaml, err := yaml.Marshal(values)
	if err != nil {
		return "", err
	}

	return string(valuesYaml), nil
}
