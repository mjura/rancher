package gke

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/rancher/norman/httperror"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/iam/v1"
)

func getOAuthClient(ctx context.Context, credentialContent string) (*http.Client, error) {
	ts, err := google.CredentialsFromJSON(ctx, []byte(credentialContent), container.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	return oauth2.NewClient(ctx, ts.TokenSource), nil
}

func getComputeServiceClient(ctx context.Context, credentialContent string) (*compute.Service, error) {
	client, err := getOAuthClient(ctx, credentialContent)

	if err != nil {
		return nil, err
	}

	service, err := compute.New(client)

	if err != nil {
		return nil, err
	}
	return service, nil
}

func getIamServiceClient(ctx context.Context, credentialContent string) (*iam.Service, error) {
	client, err := getOAuthClient(ctx, credentialContent)

	if err != nil {
		return nil, err
	}

	service, err := iam.New(client)

	if err != nil {
		return nil, err
	}
	return service, nil
}

func getContainerServiceClient(ctx context.Context, credentialContent string) (*container.Service, error) {
	client, err := getOAuthClient(ctx, credentialContent)

	if err != nil {
		return nil, err
	}

	service, err := container.New(client)

	if err != nil {
		return nil, err
	}
	return service, nil
}

func listMachineTypes(ctx context.Context, cap *Capabilities) ([]byte, int, error) {
	client, err := getComputeServiceClient(ctx, cap.Credentials)
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	result, err := client.MachineTypes.List(cap.ProjectID, cap.Zone).Do()
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	data, err := json.Marshal(&result)
	if err != nil {
		return data, httperror.ServerError.Status, err
	}

	return data, http.StatusOK, err
}

func listNetworks(ctx context.Context, cap *Capabilities) ([]byte, int, error) {
	client, err := getComputeServiceClient(ctx, cap.Credentials)
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	result, err := client.Networks.List(cap.ProjectID).Do()
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	data, err := json.Marshal(&result)
	if err != nil {
		return data, httperror.ServerError.Status, err
	}

	return data, http.StatusOK, err
}

func listSubnetworks(ctx context.Context, cap *Capabilities) ([]byte, int, error) {
	client, err := getComputeServiceClient(ctx, cap.Credentials)
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	result, err := client.Subnetworks.List(cap.ProjectID, cap.Region).Do()
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	data, err := json.Marshal(&result)
	if err != nil {
		return data, httperror.ServerError.Status, err
	}

	return data, http.StatusOK, err
}

func listServiceAccounts(ctx context.Context, cap *Capabilities) ([]byte, int, error) {
	client, err := getIamServiceClient(ctx, cap.Credentials)
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	name := "projects/" + cap.ProjectID
	result, err := client.Projects.ServiceAccounts.List(name).Do()
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	data, err := json.Marshal(&result)
	if err != nil {
		return data, httperror.ServerError.Status, err
	}

	return data, http.StatusOK, err
}

func listVersions(ctx context.Context, cap *Capabilities) ([]byte, int, error) {
	client, err := getContainerServiceClient(ctx, cap.Credentials)
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	result, err := client.Projects.Zones.GetServerconfig(cap.ProjectID, cap.Zone).Do()
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	data, err := json.Marshal(&result)
	if err != nil {
		return data, httperror.ServerError.Status, err
	}

	return data, http.StatusOK, err
}

func listZones(ctx context.Context, cap *Capabilities) ([]byte, int, error) {
	client, err := getComputeServiceClient(ctx, cap.Credentials)
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	result, err := client.Zones.List(cap.ProjectID).Do()
	if err != nil {
		return nil, httperror.ServerError.Status, err
	}

	data, err := json.Marshal(&result)
	if err != nil {
		return data, httperror.ServerError.Status, err
	}

	return data, http.StatusOK, err
}
