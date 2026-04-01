// Package gcp provides shared GCP client helpers.
package gcp

import (
	"context"
	"fmt"

	asset "cloud.google.com/go/asset/apiv1"
	compute "cloud.google.com/go/compute/apiv1"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/storage"
	admin "google.golang.org/api/iam/v1"
)

// Clients bundles GCP API clients. Each is lazily initialized on first use.
type Clients struct {
	ctx context.Context

	asset          *asset.Client
	projects       *resourcemanager.ProjectsClient
	firewalls      *compute.FirewallsClient
	storageClient  *storage.Client
	iamAdmin       *admin.Service
	securityCenter *securitycenter.Client
}

// NewClients creates a Clients struct. Actual connections are lazy.
func NewClients(ctx context.Context) *Clients {
	return &Clients{ctx: ctx}
}

func (c *Clients) Asset() (*asset.Client, error) {
	if c.asset == nil {
		var err error
		c.asset, err = asset.NewClient(c.ctx)
		if err != nil {
			return nil, fmt.Errorf("asset client: %w", err)
		}
	}
	return c.asset, nil
}

func (c *Clients) Projects() (*resourcemanager.ProjectsClient, error) {
	if c.projects == nil {
		var err error
		c.projects, err = resourcemanager.NewProjectsClient(c.ctx)
		if err != nil {
			return nil, fmt.Errorf("projects client: %w", err)
		}
	}
	return c.projects, nil
}

func (c *Clients) Firewalls() (*compute.FirewallsClient, error) {
	if c.firewalls == nil {
		var err error
		c.firewalls, err = compute.NewFirewallsRESTClient(c.ctx)
		if err != nil {
			return nil, fmt.Errorf("firewalls client: %w", err)
		}
	}
	return c.firewalls, nil
}

func (c *Clients) Storage() (*storage.Client, error) {
	if c.storageClient == nil {
		var err error
		c.storageClient, err = storage.NewClient(c.ctx)
		if err != nil {
			return nil, fmt.Errorf("storage client: %w", err)
		}
	}
	return c.storageClient, nil
}

func (c *Clients) IAMAdmin() (*admin.Service, error) {
	if c.iamAdmin == nil {
		var err error
		c.iamAdmin, err = admin.NewService(c.ctx)
		if err != nil {
			return nil, fmt.Errorf("iam admin client: %w", err)
		}
	}
	return c.iamAdmin, nil
}

func (c *Clients) SecurityCenter() (*securitycenter.Client, error) {
	if c.securityCenter == nil {
		var err error
		c.securityCenter, err = securitycenter.NewClient(c.ctx)
		if err != nil {
			return nil, fmt.Errorf("security center client: %w", err)
		}
	}
	return c.securityCenter, nil
}

// Close cleans up all open clients.
func (c *Clients) Close() {
	if c.asset != nil {
		c.asset.Close()
	}
	if c.projects != nil {
		c.projects.Close()
	}
	if c.firewalls != nil {
		c.firewalls.Close()
	}
	if c.storageClient != nil {
		c.storageClient.Close()
	}
	if c.securityCenter != nil {
		c.securityCenter.Close()
	}
}
