/*
Copyright 2021 Rancher Labs, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by codegen. DO NOT EDIT.

package v3

import (
	"context"
	"time"

	"github.com/rancher/lasso/pkg/client"
	"github.com/rancher/lasso/pkg/controller"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/apply"
	"github.com/rancher/wrangler/pkg/condition"
	"github.com/rancher/wrangler/pkg/generic"
	"github.com/rancher/wrangler/pkg/kv"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

type ClusterAlertGroupHandler func(string, *v3.ClusterAlertGroup) (*v3.ClusterAlertGroup, error)

type ClusterAlertGroupController interface {
	generic.ControllerMeta
	ClusterAlertGroupClient

	OnChange(ctx context.Context, name string, sync ClusterAlertGroupHandler)
	OnRemove(ctx context.Context, name string, sync ClusterAlertGroupHandler)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, duration time.Duration)

	Cache() ClusterAlertGroupCache
}

type ClusterAlertGroupClient interface {
	Create(*v3.ClusterAlertGroup) (*v3.ClusterAlertGroup, error)
	Update(*v3.ClusterAlertGroup) (*v3.ClusterAlertGroup, error)
	UpdateStatus(*v3.ClusterAlertGroup) (*v3.ClusterAlertGroup, error)
	Delete(namespace, name string, options *metav1.DeleteOptions) error
	Get(namespace, name string, options metav1.GetOptions) (*v3.ClusterAlertGroup, error)
	List(namespace string, opts metav1.ListOptions) (*v3.ClusterAlertGroupList, error)
	Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error)
	Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.ClusterAlertGroup, err error)
}

type ClusterAlertGroupCache interface {
	Get(namespace, name string) (*v3.ClusterAlertGroup, error)
	List(namespace string, selector labels.Selector) ([]*v3.ClusterAlertGroup, error)

	AddIndexer(indexName string, indexer ClusterAlertGroupIndexer)
	GetByIndex(indexName, key string) ([]*v3.ClusterAlertGroup, error)
}

type ClusterAlertGroupIndexer func(obj *v3.ClusterAlertGroup) ([]string, error)

type clusterAlertGroupController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewClusterAlertGroupController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) ClusterAlertGroupController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &clusterAlertGroupController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromClusterAlertGroupHandlerToHandler(sync ClusterAlertGroupHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v3.ClusterAlertGroup
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v3.ClusterAlertGroup))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *clusterAlertGroupController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v3.ClusterAlertGroup))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateClusterAlertGroupDeepCopyOnChange(client ClusterAlertGroupClient, obj *v3.ClusterAlertGroup, handler func(obj *v3.ClusterAlertGroup) (*v3.ClusterAlertGroup, error)) (*v3.ClusterAlertGroup, error) {
	if obj == nil {
		return obj, nil
	}

	copyObj := obj.DeepCopy()
	newObj, err := handler(copyObj)
	if newObj != nil {
		copyObj = newObj
	}
	if obj.ResourceVersion == copyObj.ResourceVersion && !equality.Semantic.DeepEqual(obj, copyObj) {
		return client.Update(copyObj)
	}

	return copyObj, err
}

func (c *clusterAlertGroupController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *clusterAlertGroupController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *clusterAlertGroupController) OnChange(ctx context.Context, name string, sync ClusterAlertGroupHandler) {
	c.AddGenericHandler(ctx, name, FromClusterAlertGroupHandlerToHandler(sync))
}

func (c *clusterAlertGroupController) OnRemove(ctx context.Context, name string, sync ClusterAlertGroupHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromClusterAlertGroupHandlerToHandler(sync)))
}

func (c *clusterAlertGroupController) Enqueue(namespace, name string) {
	c.controller.Enqueue(namespace, name)
}

func (c *clusterAlertGroupController) EnqueueAfter(namespace, name string, duration time.Duration) {
	c.controller.EnqueueAfter(namespace, name, duration)
}

func (c *clusterAlertGroupController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *clusterAlertGroupController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *clusterAlertGroupController) Cache() ClusterAlertGroupCache {
	return &clusterAlertGroupCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *clusterAlertGroupController) Create(obj *v3.ClusterAlertGroup) (*v3.ClusterAlertGroup, error) {
	result := &v3.ClusterAlertGroup{}
	return result, c.client.Create(context.TODO(), obj.Namespace, obj, result, metav1.CreateOptions{})
}

func (c *clusterAlertGroupController) Update(obj *v3.ClusterAlertGroup) (*v3.ClusterAlertGroup, error) {
	result := &v3.ClusterAlertGroup{}
	return result, c.client.Update(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *clusterAlertGroupController) UpdateStatus(obj *v3.ClusterAlertGroup) (*v3.ClusterAlertGroup, error) {
	result := &v3.ClusterAlertGroup{}
	return result, c.client.UpdateStatus(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *clusterAlertGroupController) Delete(namespace, name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), namespace, name, *options)
}

func (c *clusterAlertGroupController) Get(namespace, name string, options metav1.GetOptions) (*v3.ClusterAlertGroup, error) {
	result := &v3.ClusterAlertGroup{}
	return result, c.client.Get(context.TODO(), namespace, name, result, options)
}

func (c *clusterAlertGroupController) List(namespace string, opts metav1.ListOptions) (*v3.ClusterAlertGroupList, error) {
	result := &v3.ClusterAlertGroupList{}
	return result, c.client.List(context.TODO(), namespace, result, opts)
}

func (c *clusterAlertGroupController) Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), namespace, opts)
}

func (c *clusterAlertGroupController) Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (*v3.ClusterAlertGroup, error) {
	result := &v3.ClusterAlertGroup{}
	return result, c.client.Patch(context.TODO(), namespace, name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type clusterAlertGroupCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *clusterAlertGroupCache) Get(namespace, name string) (*v3.ClusterAlertGroup, error) {
	obj, exists, err := c.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v3.ClusterAlertGroup), nil
}

func (c *clusterAlertGroupCache) List(namespace string, selector labels.Selector) (ret []*v3.ClusterAlertGroup, err error) {

	err = cache.ListAllByNamespace(c.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.ClusterAlertGroup))
	})

	return ret, err
}

func (c *clusterAlertGroupCache) AddIndexer(indexName string, indexer ClusterAlertGroupIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v3.ClusterAlertGroup))
		},
	}))
}

func (c *clusterAlertGroupCache) GetByIndex(indexName, key string) (result []*v3.ClusterAlertGroup, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v3.ClusterAlertGroup, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v3.ClusterAlertGroup))
	}
	return result, nil
}

type ClusterAlertGroupStatusHandler func(obj *v3.ClusterAlertGroup, status v3.AlertStatus) (v3.AlertStatus, error)

type ClusterAlertGroupGeneratingHandler func(obj *v3.ClusterAlertGroup, status v3.AlertStatus) ([]runtime.Object, v3.AlertStatus, error)

func RegisterClusterAlertGroupStatusHandler(ctx context.Context, controller ClusterAlertGroupController, condition condition.Cond, name string, handler ClusterAlertGroupStatusHandler) {
	statusHandler := &clusterAlertGroupStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, FromClusterAlertGroupHandlerToHandler(statusHandler.sync))
}

func RegisterClusterAlertGroupGeneratingHandler(ctx context.Context, controller ClusterAlertGroupController, apply apply.Apply,
	condition condition.Cond, name string, handler ClusterAlertGroupGeneratingHandler, opts *generic.GeneratingHandlerOptions) {
	statusHandler := &clusterAlertGroupGeneratingHandler{
		ClusterAlertGroupGeneratingHandler: handler,
		apply:                              apply,
		name:                               name,
		gvk:                                controller.GroupVersionKind(),
	}
	if opts != nil {
		statusHandler.opts = *opts
	}
	controller.OnChange(ctx, name, statusHandler.Remove)
	RegisterClusterAlertGroupStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type clusterAlertGroupStatusHandler struct {
	client    ClusterAlertGroupClient
	condition condition.Cond
	handler   ClusterAlertGroupStatusHandler
}

func (a *clusterAlertGroupStatusHandler) sync(key string, obj *v3.ClusterAlertGroup) (*v3.ClusterAlertGroup, error) {
	if obj == nil {
		return obj, nil
	}

	origStatus := obj.Status.DeepCopy()
	obj = obj.DeepCopy()
	newStatus, err := a.handler(obj, obj.Status)
	if err != nil {
		// Revert to old status on error
		newStatus = *origStatus.DeepCopy()
	}

	if a.condition != "" {
		if errors.IsConflict(err) {
			a.condition.SetError(&newStatus, "", nil)
		} else {
			a.condition.SetError(&newStatus, "", err)
		}
	}
	if !equality.Semantic.DeepEqual(origStatus, &newStatus) {
		if a.condition != "" {
			// Since status has changed, update the lastUpdatedTime
			a.condition.LastUpdated(&newStatus, time.Now().UTC().Format(time.RFC3339))
		}

		var newErr error
		obj.Status = newStatus
		newObj, newErr := a.client.UpdateStatus(obj)
		if err == nil {
			err = newErr
		}
		if newErr == nil {
			obj = newObj
		}
	}
	return obj, err
}

type clusterAlertGroupGeneratingHandler struct {
	ClusterAlertGroupGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
}

func (a *clusterAlertGroupGeneratingHandler) Remove(key string, obj *v3.ClusterAlertGroup) (*v3.ClusterAlertGroup, error) {
	if obj != nil {
		return obj, nil
	}

	obj = &v3.ClusterAlertGroup{}
	obj.Namespace, obj.Name = kv.RSplit(key, "/")
	obj.SetGroupVersionKind(a.gvk)

	return nil, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects()
}

func (a *clusterAlertGroupGeneratingHandler) Handle(obj *v3.ClusterAlertGroup, status v3.AlertStatus) (v3.AlertStatus, error) {
	objs, newStatus, err := a.ClusterAlertGroupGeneratingHandler(obj, status)
	if err != nil {
		return newStatus, err
	}

	return newStatus, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects(objs...)
}
