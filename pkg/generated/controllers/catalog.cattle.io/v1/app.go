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

package v1

import (
	"context"
	"time"

	"github.com/rancher/lasso/pkg/client"
	"github.com/rancher/lasso/pkg/controller"
	v1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
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

type AppHandler func(string, *v1.App) (*v1.App, error)

type AppController interface {
	generic.ControllerMeta
	AppClient

	OnChange(ctx context.Context, name string, sync AppHandler)
	OnRemove(ctx context.Context, name string, sync AppHandler)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, duration time.Duration)

	Cache() AppCache
}

type AppClient interface {
	Create(*v1.App) (*v1.App, error)
	Update(*v1.App) (*v1.App, error)
	UpdateStatus(*v1.App) (*v1.App, error)
	Delete(namespace, name string, options *metav1.DeleteOptions) error
	Get(namespace, name string, options metav1.GetOptions) (*v1.App, error)
	List(namespace string, opts metav1.ListOptions) (*v1.AppList, error)
	Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error)
	Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (result *v1.App, err error)
}

type AppCache interface {
	Get(namespace, name string) (*v1.App, error)
	List(namespace string, selector labels.Selector) ([]*v1.App, error)

	AddIndexer(indexName string, indexer AppIndexer)
	GetByIndex(indexName, key string) ([]*v1.App, error)
}

type AppIndexer func(obj *v1.App) ([]string, error)

type appController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewAppController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) AppController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &appController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromAppHandlerToHandler(sync AppHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v1.App
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v1.App))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *appController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v1.App))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateAppDeepCopyOnChange(client AppClient, obj *v1.App, handler func(obj *v1.App) (*v1.App, error)) (*v1.App, error) {
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

func (c *appController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *appController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *appController) OnChange(ctx context.Context, name string, sync AppHandler) {
	c.AddGenericHandler(ctx, name, FromAppHandlerToHandler(sync))
}

func (c *appController) OnRemove(ctx context.Context, name string, sync AppHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromAppHandlerToHandler(sync)))
}

func (c *appController) Enqueue(namespace, name string) {
	c.controller.Enqueue(namespace, name)
}

func (c *appController) EnqueueAfter(namespace, name string, duration time.Duration) {
	c.controller.EnqueueAfter(namespace, name, duration)
}

func (c *appController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *appController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *appController) Cache() AppCache {
	return &appCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *appController) Create(obj *v1.App) (*v1.App, error) {
	result := &v1.App{}
	return result, c.client.Create(context.TODO(), obj.Namespace, obj, result, metav1.CreateOptions{})
}

func (c *appController) Update(obj *v1.App) (*v1.App, error) {
	result := &v1.App{}
	return result, c.client.Update(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *appController) UpdateStatus(obj *v1.App) (*v1.App, error) {
	result := &v1.App{}
	return result, c.client.UpdateStatus(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *appController) Delete(namespace, name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), namespace, name, *options)
}

func (c *appController) Get(namespace, name string, options metav1.GetOptions) (*v1.App, error) {
	result := &v1.App{}
	return result, c.client.Get(context.TODO(), namespace, name, result, options)
}

func (c *appController) List(namespace string, opts metav1.ListOptions) (*v1.AppList, error) {
	result := &v1.AppList{}
	return result, c.client.List(context.TODO(), namespace, result, opts)
}

func (c *appController) Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), namespace, opts)
}

func (c *appController) Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (*v1.App, error) {
	result := &v1.App{}
	return result, c.client.Patch(context.TODO(), namespace, name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type appCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *appCache) Get(namespace, name string) (*v1.App, error) {
	obj, exists, err := c.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v1.App), nil
}

func (c *appCache) List(namespace string, selector labels.Selector) (ret []*v1.App, err error) {

	err = cache.ListAllByNamespace(c.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.App))
	})

	return ret, err
}

func (c *appCache) AddIndexer(indexName string, indexer AppIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v1.App))
		},
	}))
}

func (c *appCache) GetByIndex(indexName, key string) (result []*v1.App, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v1.App, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v1.App))
	}
	return result, nil
}

type AppStatusHandler func(obj *v1.App, status v1.ReleaseStatus) (v1.ReleaseStatus, error)

type AppGeneratingHandler func(obj *v1.App, status v1.ReleaseStatus) ([]runtime.Object, v1.ReleaseStatus, error)

func RegisterAppStatusHandler(ctx context.Context, controller AppController, condition condition.Cond, name string, handler AppStatusHandler) {
	statusHandler := &appStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, FromAppHandlerToHandler(statusHandler.sync))
}

func RegisterAppGeneratingHandler(ctx context.Context, controller AppController, apply apply.Apply,
	condition condition.Cond, name string, handler AppGeneratingHandler, opts *generic.GeneratingHandlerOptions) {
	statusHandler := &appGeneratingHandler{
		AppGeneratingHandler: handler,
		apply:                apply,
		name:                 name,
		gvk:                  controller.GroupVersionKind(),
	}
	if opts != nil {
		statusHandler.opts = *opts
	}
	controller.OnChange(ctx, name, statusHandler.Remove)
	RegisterAppStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type appStatusHandler struct {
	client    AppClient
	condition condition.Cond
	handler   AppStatusHandler
}

func (a *appStatusHandler) sync(key string, obj *v1.App) (*v1.App, error) {
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

type appGeneratingHandler struct {
	AppGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
}

func (a *appGeneratingHandler) Remove(key string, obj *v1.App) (*v1.App, error) {
	if obj != nil {
		return obj, nil
	}

	obj = &v1.App{}
	obj.Namespace, obj.Name = kv.RSplit(key, "/")
	obj.SetGroupVersionKind(a.gvk)

	return nil, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects()
}

func (a *appGeneratingHandler) Handle(obj *v1.App, status v1.ReleaseStatus) (v1.ReleaseStatus, error) {
	objs, newStatus, err := a.AppGeneratingHandler(obj, status)
	if err != nil {
		return newStatus, err
	}

	return newStatus, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects(objs...)
}
