package gke

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rancher/norman/api/access"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"
	"github.com/rancher/rancher/pkg/auth/util"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	v1 "github.com/rancher/rancher/pkg/generated/norman/core/v1"
	"github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/rancher/pkg/ref"
	schema "github.com/rancher/rancher/pkg/schemas/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
)

type Capabilities struct {
	Credentials string `json:"credentials,omitempty"`
	ProjectID   string `json:"projectId,omitempty"`
	Zone        string `json:"zone,omitempty"`
	Region      string `json:"region,omitempty"`
}

// GKE handler lists available resources in Google API
type handler struct {
	Action        string
	schemas       *types.Schemas
	secretsLister v1.SecretLister
}

func NewGKEHandler(scaledContext *config.ScaledContext) http.Handler {
	return &handler{
		schemas:       scaledContext.Schemas,
		secretsLister: scaledContext.Core.Secrets(namespace.GlobalNamespace).Controller().Lister(),
	}
}

func (h *handler) ServeHTTP(writer http.ResponseWriter, req *http.Request) {

	writer.Header().Set("Content-Type", "application/json")

	capa := &Capabilities{}

	if credID := req.URL.Query().Get("cloudCredentialId"); credID != "" {
		if err := h.getCloudCredentials(req, capa, credID); err != nil {
			return
		}

	} else if req.Method == http.MethodPost {
		err := h.getCredentialsFromBody(writer, req, capa)
		if err != nil {
			return
		}

		if capa.Region == "" {
			util.ReturnHTTPError(writer, req, httperror.InvalidBodyContent.Status, "cannot find Region name")
		}
	} else {
		util.ReturnHTTPError(writer, req, httperror.Unauthorized.Status, "cannot access Google API without credentials to authenticate")
	}

	var serialized []byte
	var errCode int
	var err error

	resourceType := mux.Vars(req)["resource"]

	switch resourceType {
	case "gkeMachineTypes":
		if serialized, errCode, err = listMachineTypes(req.Context(), capa); err != nil {
			logrus.Debugf("[gke-handler] error getting machine types: %v", err)
			util.ReturnHTTPError(writer, req, errCode, err.Error())
			return
		}
		writer.Write(serialized)
	case "gkeNetworks":
		if serialized, errCode, err = listNetworks(req.Context(), capa); err != nil {
			logrus.Debugf("[gke-handler] error getting networks: %v", err)
			util.ReturnHTTPError(writer, req, errCode, err.Error())
			return
		}
		writer.Write(serialized)
	case "gkeServiceAccounts":
		if serialized, errCode, err = listServiceAccounts(req.Context(), capa); err != nil {
			logrus.Debugf("[gke-handler] error getting serviceaccounts: %v", err)
			util.ReturnHTTPError(writer, req, errCode, err.Error())
			return
		}
		writer.Write(serialized)
	case "gkeSubnetworks":
		if serialized, errCode, err = listSubnetworks(req.Context(), capa); err != nil {
			logrus.Debugf("[gke-handler] error getting subnetworks: %v", err)
			util.ReturnHTTPError(writer, req, errCode, err.Error())
			return
		}
		writer.Write(serialized)
	case "gkeVersions":
		if serialized, errCode, err = listVersions(req.Context(), capa); err != nil {
			logrus.Debugf("[gke-handler] error getting versions: %v", err)
			util.ReturnHTTPError(writer, req, errCode, err.Error())
			return
		}
		writer.Write(serialized)
	case "gkeZones":
		if serialized, errCode, err = listZones(req.Context(), capa); err != nil {
			logrus.Debugf("[gke-handler] error getting zones: %v", err)
			util.ReturnHTTPError(writer, req, errCode, err.Error())
			return
		}
		writer.Write(serialized)
	default:
		util.ReturnHTTPError(writer, req, httperror.NotFound.Status, "invalid endpoint "+resourceType)
	}
}

func (h *handler) getCloudCredentials(req *http.Request, cap *Capabilities, credID string) error {
	ns, name := ref.Parse(credID)
	if ns == "" || name == "" {
		logrus.Debugf("[GKE] invalid cloud credential ID %s", credID)
		return fmt.Errorf("invalid cloud credential ID %s", credID)
	}

	var accessCred client.CloudCredential //var to check access
	if err := access.ByID(h.generateAPIContext(req), &schema.Version, client.CloudCredentialType, credID, &accessCred); err != nil {
		if apiError, ok := err.(*httperror.APIError); ok {
			if apiError.Code.Status == httperror.PermissionDenied.Status || apiError.Code.Status == httperror.NotFound.Status {
				return fmt.Errorf("cloud credential not found")
			}
		}
		return err
	}

	cc, err := h.secretsLister.Get(namespace.GlobalNamespace, name)
	if err != nil {
		logrus.Debugf("[GKE] error accessing cloud credential %s", credID)
		return fmt.Errorf("error accessing cloud credential %s", credID)
	}
	cap.Credentials = string(cc.Data["googlecredentialConfig-authEncodedJson"])
	region := req.URL.Query().Get("region")
	if region != "" {
		cap.Region = region
	}
	zone := req.URL.Query().Get("zone")
	if zone != "" {
		cap.Zone = zone
	}
	projectId := req.URL.Query().Get("projectId")
	if projectId != "" {
		cap.ProjectID = projectId
	}

	return nil
}

func (h *handler) getCredentialsFromBody(writer http.ResponseWriter, req *http.Request, cap *Capabilities) error {
	raw, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("cannot read request body: " + err.Error())
	}

	if err = json.Unmarshal(raw, &cap); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("cannot parse request body: " + err.Error())
	}

	if cap.ProjectID == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("invalid projectId")
	}

	if cap.Credentials == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("invalid credentials")
	}

	return nil
}

func (h *handler) generateAPIContext(req *http.Request) *types.APIContext {
	return &types.APIContext{
		Method:  req.Method,
		Request: req,
		Schemas: h.schemas,
		Query:   map[string][]string{},
	}
}
