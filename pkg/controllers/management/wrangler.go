package management

import (
	"context"

	"github.com/rancher/rancher/pkg/clustermanager"
	"github.com/rancher/rancher/pkg/controllers/management/aks"
	"github.com/rancher/rancher/pkg/controllers/management/eks"
	"github.com/rancher/rancher/pkg/controllers/management/aksupstreamrefresh"
	"github.com/rancher/rancher/pkg/controllers/management/eksupstreamrefresh"
	"github.com/rancher/rancher/pkg/controllers/management/k3sbasedupgrade"
	"github.com/rancher/rancher/pkg/controllers/management/systemcharts"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/rancher/pkg/wrangler"
)

func RegisterWrangler(ctx context.Context, wranglerContext *wrangler.Context, management *config.ManagementContext, manager *clustermanager.Manager) error {
	k3sbasedupgrade.Register(ctx, wranglerContext, management, manager)
	aks.Register(ctx, wranglerContext, management)
	eks.Register(ctx, wranglerContext, management)
	aksupstreamrefresh.Register(ctx, wranglerContext)
	eksupstreamrefresh.Register(ctx, wranglerContext)
	return systemcharts.Register(ctx, wranglerContext)
}
