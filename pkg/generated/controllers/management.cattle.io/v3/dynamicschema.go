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

type DynamicSchemaHandler func(string, *v3.DynamicSchema) (*v3.DynamicSchema, error)

type DynamicSchemaController interface {
	generic.ControllerMeta
	DynamicSchemaClient

	OnChange(ctx context.Context, name string, sync DynamicSchemaHandler)
	OnRemove(ctx context.Context, name string, sync DynamicSchemaHandler)
	Enqueue(name string)
	EnqueueAfter(name string, duration time.Duration)

	Cache() DynamicSchemaCache
}

type DynamicSchemaClient interface {
	Create(*v3.DynamicSchema) (*v3.DynamicSchema, error)
	Update(*v3.DynamicSchema) (*v3.DynamicSchema, error)
	UpdateStatus(*v3.DynamicSchema) (*v3.DynamicSchema, error)
	Delete(name string, options *metav1.DeleteOptions) error
	Get(name string, options metav1.GetOptions) (*v3.DynamicSchema, error)
	List(opts metav1.ListOptions) (*v3.DynamicSchemaList, error)
	Watch(opts metav1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.DynamicSchema, err error)
}

type DynamicSchemaCache interface {
	Get(name string) (*v3.DynamicSchema, error)
	List(selector labels.Selector) ([]*v3.DynamicSchema, error)

	AddIndexer(indexName string, indexer DynamicSchemaIndexer)
	GetByIndex(indexName, key string) ([]*v3.DynamicSchema, error)
}

type DynamicSchemaIndexer func(obj *v3.DynamicSchema) ([]string, error)

type dynamicSchemaController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewDynamicSchemaController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) DynamicSchemaController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &dynamicSchemaController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromDynamicSchemaHandlerToHandler(sync DynamicSchemaHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v3.DynamicSchema
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v3.DynamicSchema))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *dynamicSchemaController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v3.DynamicSchema))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateDynamicSchemaDeepCopyOnChange(client DynamicSchemaClient, obj *v3.DynamicSchema, handler func(obj *v3.DynamicSchema) (*v3.DynamicSchema, error)) (*v3.DynamicSchema, error) {
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

func (c *dynamicSchemaController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *dynamicSchemaController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *dynamicSchemaController) OnChange(ctx context.Context, name string, sync DynamicSchemaHandler) {
	c.AddGenericHandler(ctx, name, FromDynamicSchemaHandlerToHandler(sync))
}

func (c *dynamicSchemaController) OnRemove(ctx context.Context, name string, sync DynamicSchemaHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromDynamicSchemaHandlerToHandler(sync)))
}

func (c *dynamicSchemaController) Enqueue(name string) {
	c.controller.Enqueue("", name)
}

func (c *dynamicSchemaController) EnqueueAfter(name string, duration time.Duration) {
	c.controller.EnqueueAfter("", name, duration)
}

func (c *dynamicSchemaController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *dynamicSchemaController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *dynamicSchemaController) Cache() DynamicSchemaCache {
	return &dynamicSchemaCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *dynamicSchemaController) Create(obj *v3.DynamicSchema) (*v3.DynamicSchema, error) {
	result := &v3.DynamicSchema{}
	return result, c.client.Create(context.TODO(), "", obj, result, metav1.CreateOptions{})
}

func (c *dynamicSchemaController) Update(obj *v3.DynamicSchema) (*v3.DynamicSchema, error) {
	result := &v3.DynamicSchema{}
	return result, c.client.Update(context.TODO(), "", obj, result, metav1.UpdateOptions{})
}

func (c *dynamicSchemaController) UpdateStatus(obj *v3.DynamicSchema) (*v3.DynamicSchema, error) {
	result := &v3.DynamicSchema{}
	return result, c.client.UpdateStatus(context.TODO(), "", obj, result, metav1.UpdateOptions{})
}

func (c *dynamicSchemaController) Delete(name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), "", name, *options)
}

func (c *dynamicSchemaController) Get(name string, options metav1.GetOptions) (*v3.DynamicSchema, error) {
	result := &v3.DynamicSchema{}
	return result, c.client.Get(context.TODO(), "", name, result, options)
}

func (c *dynamicSchemaController) List(opts metav1.ListOptions) (*v3.DynamicSchemaList, error) {
	result := &v3.DynamicSchemaList{}
	return result, c.client.List(context.TODO(), "", result, opts)
}

func (c *dynamicSchemaController) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), "", opts)
}

func (c *dynamicSchemaController) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (*v3.DynamicSchema, error) {
	result := &v3.DynamicSchema{}
	return result, c.client.Patch(context.TODO(), "", name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type dynamicSchemaCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *dynamicSchemaCache) Get(name string) (*v3.DynamicSchema, error) {
	obj, exists, err := c.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v3.DynamicSchema), nil
}

func (c *dynamicSchemaCache) List(selector labels.Selector) (ret []*v3.DynamicSchema, err error) {

	err = cache.ListAll(c.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.DynamicSchema))
	})

	return ret, err
}

func (c *dynamicSchemaCache) AddIndexer(indexName string, indexer DynamicSchemaIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v3.DynamicSchema))
		},
	}))
}

func (c *dynamicSchemaCache) GetByIndex(indexName, key string) (result []*v3.DynamicSchema, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v3.DynamicSchema, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v3.DynamicSchema))
	}
	return result, nil
}

type DynamicSchemaStatusHandler func(obj *v3.DynamicSchema, status v3.DynamicSchemaStatus) (v3.DynamicSchemaStatus, error)

type DynamicSchemaGeneratingHandler func(obj *v3.DynamicSchema, status v3.DynamicSchemaStatus) ([]runtime.Object, v3.DynamicSchemaStatus, error)

func RegisterDynamicSchemaStatusHandler(ctx context.Context, controller DynamicSchemaController, condition condition.Cond, name string, handler DynamicSchemaStatusHandler) {
	statusHandler := &dynamicSchemaStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, FromDynamicSchemaHandlerToHandler(statusHandler.sync))
}

func RegisterDynamicSchemaGeneratingHandler(ctx context.Context, controller DynamicSchemaController, apply apply.Apply,
	condition condition.Cond, name string, handler DynamicSchemaGeneratingHandler, opts *generic.GeneratingHandlerOptions) {
	statusHandler := &dynamicSchemaGeneratingHandler{
		DynamicSchemaGeneratingHandler: handler,
		apply:                          apply,
		name:                           name,
		gvk:                            controller.GroupVersionKind(),
	}
	if opts != nil {
		statusHandler.opts = *opts
	}
	controller.OnChange(ctx, name, statusHandler.Remove)
	RegisterDynamicSchemaStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type dynamicSchemaStatusHandler struct {
	client    DynamicSchemaClient
	condition condition.Cond
	handler   DynamicSchemaStatusHandler
}

func (a *dynamicSchemaStatusHandler) sync(key string, obj *v3.DynamicSchema) (*v3.DynamicSchema, error) {
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

type dynamicSchemaGeneratingHandler struct {
	DynamicSchemaGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
}

func (a *dynamicSchemaGeneratingHandler) Remove(key string, obj *v3.DynamicSchema) (*v3.DynamicSchema, error) {
	if obj != nil {
		return obj, nil
	}

	obj = &v3.DynamicSchema{}
	obj.Namespace, obj.Name = kv.RSplit(key, "/")
	obj.SetGroupVersionKind(a.gvk)

	return nil, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects()
}

func (a *dynamicSchemaGeneratingHandler) Handle(obj *v3.DynamicSchema, status v3.DynamicSchemaStatus) (v3.DynamicSchemaStatus, error) {
	objs, newStatus, err := a.DynamicSchemaGeneratingHandler(obj, status)
	if err != nil {
		return newStatus, err
	}

	return newStatus, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects(objs...)
}
